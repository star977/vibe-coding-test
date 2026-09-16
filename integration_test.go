package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ═══════════════════════════════════════════════════════════════
// 集成测试：让探测经过真实的 UDP 套接字收发与 DNS 报文编解码。
//
// 与 scan_test.go 的区别：那里直接在内存里构造已解包的消息，
// 跳过了收发与三段式问答；这里起一个真实的 UDP 服务端按 DNS-SD
// 规则应答，因此 send / collect / run 的三段式流程、报文往返、
// 解析、聚合、渲染全程都被覆盖。
// ═══════════════════════════════════════════════════════════════

// fakeResponder 是一个真实的 UDP 服务端，按 mDNS/DNS-SD 的问答规则应答。
type fakeResponder struct {
	conn     *net.UDPConn
	port     int
	hostname string
	v4, v6   string
	svcs     []fakeSvc

	// answerOnlyMeta 为真时只应答元查询，对后续的服务类型查询保持沉默。
	// 这样的目标会耗满整个时间预算（因为元查询有应答，不触发早退），
	// 用于验证 §9.6-C4：单个慢目标不得拖垮其余地址。
	answerOnlyMeta bool

	// packetsPerQuery 控制每个查询回几个报文。
	// 设为 2 可覆盖 §4.3 节点③b 的边界：同一地址可能返回多个报文，
	// 不能收到第一个就停。
	packetsPerQuery int

	mu   sync.Mutex
	seen []string // 收到过的查询名，供断言种子查询确实发出

	done chan struct{}
	wg   sync.WaitGroup
}

func startFakeResponder(t *testing.T, r *fakeResponder) *fakeResponder {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("假响应端监听失败: %v", err)
	}
	r.conn = conn
	r.port = conn.LocalAddr().(*net.UDPAddr).Port
	r.done = make(chan struct{})
	if r.packetsPerQuery == 0 {
		r.packetsPerQuery = 1
	}
	r.wg.Add(1)
	go r.serve()
	t.Cleanup(func() {
		close(r.done)
		_ = conn.Close()
		r.wg.Wait()
	})
	return r
}

func (r *fakeResponder) serve() {
	defer r.wg.Done()
	buf := make([]byte, maxPacket)
	for {
		select {
		case <-r.done:
			return
		default:
		}
		_ = r.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, addr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-r.done:
				return
			default:
				continue // 读超时，继续轮询
			}
		}
		q := new(dns.Msg)
		if q.Unpack(buf[:n]) != nil || len(q.Question) == 0 {
			continue
		}
		name := strings.ToLower(q.Question[0].Name)

		r.mu.Lock()
		r.seen = append(r.seen, name)
		r.mu.Unlock()

		resp := r.answer(q, name)
		if resp == nil {
			continue
		}
		raw, err := resp.Pack()
		if err != nil {
			continue
		}
		for i := 0; i < r.packetsPerQuery; i++ {
			_, _ = r.conn.WriteToUDP(raw, addr)
		}
	}
}

func (r *fakeResponder) answer(q *dns.Msg, name string) *dns.Msg {
	// TTL 固定为 10，模拟 RFC 6762 §6.7 对源端口非 5353 查询的处理。
	hdr := func(n string, rt uint16) dns.RR_Header {
		return dns.RR_Header{Name: n, Rrtype: rt, Class: dns.ClassINET, Ttl: 10}
	}
	m := new(dns.Msg)
	m.SetReply(q)
	m.Authoritative = true

	if name == strings.ToLower(metaQuery) {
		for _, s := range r.svcs {
			m.Answer = append(m.Answer,
				&dns.PTR{Hdr: hdr(metaQuery, dns.TypePTR), Ptr: "_" + s.typ + "._tcp.local."})
		}
		return m
	}

	if r.answerOnlyMeta {
		return nil // 对非元查询保持沉默
	}

	for _, s := range r.svcs {
		svcType := "_" + s.typ + "._tcp.local."
		if !strings.EqualFold(name, svcType) {
			continue
		}
		inst := s.instance + "." + svcType
		m.Answer = append(m.Answer, &dns.PTR{Hdr: hdr(svcType, dns.TypePTR), Ptr: inst})
		// §8.3：把定位记录、描述记录与地址记录塞进附加区随 PTR 一起返回，
		// 这是真实设备的常见行为，也是「先榨干附加区」的验证对象。
		if s.port != 0 {
			m.Extra = append(m.Extra,
				&dns.SRV{Hdr: hdr(inst, dns.TypeSRV), Port: s.port, Target: r.hostname})
		}
		if len(s.txt) > 0 {
			m.Extra = append(m.Extra, &dns.TXT{Hdr: hdr(inst, dns.TypeTXT), Txt: s.txt})
		}
		if r.v4 != "" {
			m.Extra = append(m.Extra,
				&dns.A{Hdr: hdr(r.hostname, dns.TypeA), A: net.ParseIP(r.v4)})
		}
		if r.v6 != "" {
			m.Extra = append(m.Extra,
				&dns.AAAA{Hdr: hdr(r.hostname, dns.TypeAAAA), AAAA: net.ParseIP(r.v6)})
		}
		return m
	}
	return m // 未知类型回空应答，模拟设备对无关查询的沉默
}

func (r *fakeResponder) sawQuery(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.seen {
		if strings.EqualFold(s, name) {
			return true
		}
	}
	return false
}

// routeByLastOctet 按目标地址的末位字节把 dial 定向到不同的本地端口，
// 从而在同一次扫描里模拟行为各异的多个目标。
// 未在映射表中的地址被导向本地一个只收不回的黑洞端口。
func routeByLastOctet(t *testing.T, ports map[byte]int, fallback int) {
	t.Helper()
	orig := dialUDP
	t.Cleanup(func() { dialUDP = orig })
	dialUDP = func(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
		v4 := raddr.IP.To4()
		if v4 == nil {
			return orig(network, laddr, raddr)
		}
		port, ok := ports[v4[3]]
		if !ok {
			port = fallback
		}
		return orig(network, laddr, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	}
}

// pointProbesAtFake 把协议端口改指假响应端。
func pointProbesAtFake(t *testing.T, r *fakeResponder) {
	t.Helper()
	orig := mdnsPort
	mdnsPort = r.port
	t.Cleanup(func() { mdnsPort = orig })
}

func nasResponder() *fakeResponder {
	return &fakeResponder{
		hostname: "slw-nas.local.",
		v4:       "127.0.0.1",
		v6:       "fe80::265e:beff:fe69:a313",
		svcs: []fakeSvc{
			{typ: "workstation", instance: "slw-nas [24:5e:be:69:a3:13]", port: 9},
			{typ: "qdiscover", instance: "slw-nas", port: 5000, txt: []string{
				"accessType=https", "accessPort=86", "model=TS-X64",
				"displayModel=TS-464C", "fwVer=5.2.9", "fwBuildNum=20260214"}},
			{typ: "device-info", instance: "slw-nas", port: 0, txt: []string{"model=Xserve"}},
		},
	}
}

// TestIntegrationUnicastFullStack 走完整链路：
// 真实 UDP 收发 → 三段式查询 → 报文解析 → 聚合过滤 → 渲染输出。
func TestIntegrationUnicastFullStack(t *testing.T) {
	r := startFakeResponder(t, nasResponder())
	pointProbesAtFake(t, r)

	msgs, probeErr := probeUnicast(context.Background(), net.ParseIP("127.0.0.1"), 2*time.Second)
	if probeErr != nil {
		t.Fatalf("套接字创建失败: %v", probeErr)
	}
	if len(msgs) == 0 {
		t.Fatal("未收到任何响应，真实 UDP 往返失败")
	}

	// 三段式确实发生了：元查询与具体服务类型查询都应被收到。
	if !r.sawQuery(metaQuery) {
		t.Error("未收到元查询，Q1 阶段未执行")
	}
	if !r.sawQuery("_qdiscover._tcp.local.") {
		t.Error("未收到服务类型查询，Q2 阶段未执行")
	}

	_, ipnet, err := net.ParseCIDR("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	hosts := aggregate(map[string][]recvMsg{"127.0.0.1": msgs},
		Config{Net: ipnet, PortMin: 1, PortMax: 65535})
	if len(hosts) != 1 {
		t.Fatalf("期望聚合出 1 台设备，实际 %d 台", len(hosts))
	}
	out := renderAll(hosts)

	// 逐项核对：从线缆上取回的数据必须完整落到输出里。
	wants := []struct{ spec, want string }{
		{"F4 端口", "9/tcp workstation:"},
		{"§4.4 无端口服务", "\ndevice-info:\n"},
		{"§7.3-① 转义还原", "Name=slw-nas [24:5e:be:69:a3:13]"},
		{"F5 主机名", "Hostname=slw-nas.local"},
		{"F3 IPv4", "IPv4=127.0.0.1"},
		{"§7.2 IPv6", "IPv6=fe80::265e:beff:fe69:a313"},
		{"TTL", "TTL=10"},
		{"F6 深度标识完整且保序", "accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214"},
		{"F9 answers 段", "answers:\nPTR:\n"},
	}
	for _, w := range wants {
		if !strings.Contains(out, w.want) {
			t.Errorf("%s：输出中未找到 %q\n完整输出:\n%s", w.spec, w.want, out)
		}
	}
}

// TestIntegrationMulticastPath 走通组播通道的代码路径。
//
// 把组地址改指 127.0.0.1：发送与收包逻辑与真实组播完全一致，
// 只是目的地址不同，因此无需依赖真实组播环境即可验证
// 种子查询是否真的发到了线缆上。
func TestIntegrationMulticastPath(t *testing.T) {
	r := startFakeResponder(t, nasResponder())
	pointProbesAtFake(t, r)

	origGroup := mdnsGroupV4
	mdnsGroupV4 = net.ParseIP("127.0.0.1")
	t.Cleanup(func() { mdnsGroupV4 = origGroup })

	msgs, err := probeMulticast(context.Background(), 2*time.Second)
	if err != nil {
		t.Fatalf("组播通道出错: %v", err)
	}
	if len(msgs) == 0 {
		t.Fatal("组播通道未收到任何响应")
	}

	// F12：种子服务类型必须真的发到线缆上，而非只存在于代码里。
	for _, seed := range []string{"_qdiscover._tcp.local.", "_ipp._tcp.local.", "_hap._tcp.local."} {
		if !r.sawQuery(seed) {
			t.Errorf("F12：种子类型 %s 未被发送", seed)
		}
	}

	h := parseHost(net.ParseIP("127.0.0.1"), msgs)
	if h == nil {
		t.Fatal("组播响应未能解析出设备")
	}
	if len(h.Services) == 0 {
		t.Error("组播响应未解析出任何服务")
	}
}

// TestIntegrationCollectsMultiplePackets 覆盖 §4.3 节点③b 边界：
// 同一地址可能返回多个报文，不能收到第一个就停。
func TestIntegrationCollectsMultiplePackets(t *testing.T) {
	r := nasResponder()
	r.packetsPerQuery = 3
	startFakeResponder(t, r)
	pointProbesAtFake(t, r)

	msgs, probeErr := probeUnicast(context.Background(), net.ParseIP("127.0.0.1"), 2*time.Second)
	if probeErr != nil {
		t.Fatalf("套接字创建失败: %v", probeErr)
	}
	if len(msgs) < 3 {
		t.Errorf("每个查询回 3 个报文，实际只收到 %d 个报文，"+
			"说明收包提前终止", len(msgs))
	}
}

// TestIntegrationSilentTargetCostsLess 验证无响应地址的早退优化：
// 元查询无人应答时应立即收尾，而非耗满整个预算。
func TestIntegrationSilentTargetCostsLess(t *testing.T) {
	// 指向一个没有监听者的本地端口。
	orig := mdnsPort
	mdnsPort = 1 // 特权端口，本地必然无监听
	t.Cleanup(func() { mdnsPort = orig })

	const budget = 900 * time.Millisecond
	start := time.Now()
	msgs, probeErr := probeUnicast(context.Background(), net.ParseIP("127.0.0.1"), budget)
	if probeErr != nil {
		t.Fatalf("套接字创建失败: %v", probeErr)
	}
	elapsed := time.Since(start)

	if len(msgs) != 0 {
		t.Errorf("无监听者却收到 %d 个报文", len(msgs))
	}
	// 早退后应约为预算的 1/3；放宽到 2/3 以容忍调度抖动。
	if elapsed > budget*2/3 {
		t.Errorf("无响应地址耗时 %v，预算 %v，早退优化未生效", elapsed, budget)
	}
}

// TestIntegrationMalformedPacketIsSkipped 覆盖 §9.4-E3：
// 畸形报文必须被跳过且不 panic。
func TestIntegrationMalformedPacketIsSkipped(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// 回一串随机字节，不是合法 DNS 报文。
		_, _ = conn.WriteToUDP([]byte("这不是一个合法的 DNS 报文 \x00\xff\xfe"), addr)
	}()
	t.Cleanup(func() { _ = conn.Close(); <-done })

	orig := mdnsPort
	mdnsPort = port
	t.Cleanup(func() { mdnsPort = orig })

	// 不得 panic；畸形报文被跳过后结果为空。
	msgs, probeErr := probeUnicast(context.Background(), net.ParseIP("127.0.0.1"), 600*time.Millisecond)
	if probeErr != nil {
		t.Fatalf("套接字创建失败: %v", probeErr)
	}
	for _, m := range msgs {
		if m.msg == nil {
			t.Error("畸形报文被当作有效响应收下")
		}
	}
}
