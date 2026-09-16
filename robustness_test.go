package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// unreachableDial 返回一个模拟「网络不可达」的 dial 实现。
func unreachableDial() func(string, *net.UDPAddr, *net.UDPAddr) (*net.UDPConn, error) {
	return func(network string, _, raddr *net.UDPAddr) (*net.UDPConn, error) {
		return nil, &net.OpError{Op: "dial", Net: network, Addr: raddr,
			Err: errors.New("network is unreachable")}
	}
}

func smallScan(t *testing.T, cidr string, timeout time.Duration) (Config, ipRange) {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := expandCIDR(ipnet)
	if err != nil {
		t.Fatal(err)
	}
	return Config{Net: ipnet, PortMin: 1, PortMax: 65535,
		Timeout: timeout, Concurrency: 8}, targets
}

// TestE5NetworkUnusableIsReported 覆盖 §9.4-E5：
// 接口不可用时必须明确报错，**不得静默跑完再输出空**。
//
// 这条原本是实现缺口：dial 失败与「目标无响应」都走同一条静默
// 跳过的路径，接口断开时程序会照常输出「未发现资产」，
// 把环境故障伪装成扫描结果。
func TestE5NetworkUnusableIsReported(t *testing.T) {
	origDial, origListen := dialUDP, listenUDP
	t.Cleanup(func() { dialUDP, listenUDP = origDial, origListen })
	dialUDP = unreachableDial()
	listenUDP = func(string, *net.UDPAddr) (*net.UDPConn, error) {
		return nil, errors.New("network is unreachable")
	}

	cfg, targets := smallScan(t, "192.168.1.0/29", 200*time.Millisecond)
	var warn bytes.Buffer
	groups := probeAll(context.Background(), cfg, targets, &warn)

	if len(groups) != 0 {
		t.Errorf("网络不可达却收到 %d 组响应", len(groups))
	}
	out := warn.String()
	if !strings.Contains(out, "全部无法建立连接") {
		t.Errorf("§9.4-E5：未给出明确警告，实际输出 %q", out)
	}
	// 警告必须点明这与「未发现资产」不是一回事，否则等于没说。
	if !strings.Contains(out, "未发现资产") {
		t.Errorf("警告未区分环境故障与空结果，实际输出 %q", out)
	}
}

// TestE5NoFalseAlarmWhenSomeSucceed 反向确认：
// 只要有地址能连上，就不该报「全部无法建立连接」。
// 少了这条，上一个用例可以用「永远报警」来通过。
func TestE5NoFalseAlarmWhenSomeSucceed(t *testing.T) {
	r := startFakeResponder(t, nasResponder())
	pointProbesAtFake(t, r)

	origListen := listenUDP
	t.Cleanup(func() { listenUDP = origListen })
	listenUDP = func(string, *net.UDPAddr) (*net.UDPConn, error) {
		return nil, errors.New("组播禁用，与本用例无关")
	}

	cfg, targets := smallScan(t, "127.0.0.0/30", 600*time.Millisecond)
	var warn bytes.Buffer
	groups := probeAll(context.Background(), cfg, targets, &warn)

	if len(groups) == 0 {
		t.Fatal("假响应端应至少产出一组响应")
	}
	if strings.Contains(warn.String(), "全部无法建立连接") {
		t.Errorf("有地址连通却误报接口故障，实际输出 %q", warn.String())
	}
}

// TestE6PermissionDeniedSurfacesCause 覆盖 §9.4-E6：
// 无权限时须明确提示**具体原因**，而非只说「不可用」。
func TestE6PermissionDeniedSurfacesCause(t *testing.T) {
	origListen := listenUDP
	t.Cleanup(func() { listenUDP = origListen })
	listenUDP = func(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
		return nil, &net.OpError{Op: "listen", Net: network, Addr: laddr,
			Err: os.ErrPermission}
	}

	r := startFakeResponder(t, nasResponder())
	pointProbesAtFake(t, r)

	cfg, targets := smallScan(t, "127.0.0.0/30", 600*time.Millisecond)
	var warn bytes.Buffer
	probeAll(context.Background(), cfg, targets, &warn)

	out := warn.String()
	if !strings.Contains(out, "已降级为纯单播") {
		t.Errorf("§9.4-E6：未提示降级，实际输出 %q", out)
	}
	// 原因必须原样带出，否则使用者无从判断是权限、端口占用还是别的问题。
	if !strings.Contains(out, os.ErrPermission.Error()) {
		t.Errorf("§9.4-E6：未带出具体原因 %q，实际输出 %q",
			os.ErrPermission.Error(), out)
	}
}

// ═══════════════ S3 解析炸弹 / S4 内存放大 ═══════════════

// dnsHeader 手工拼一个 DNS 报文头。
// an / ar 是声明的回答区与附加区记录数，可故意与实际内容不符。
func dnsHeader(an, ar uint16) []byte {
	return []byte{
		0x12, 0x34, // ID
		0x84, 0x00, // Flags: QR=1 AA=1
		0x00, 0x00, // QDCOUNT
		byte(an >> 8), byte(an), // ANCOUNT
		0x00, 0x00, // NSCOUNT
		byte(ar >> 8), byte(ar), // ARCOUNT
	}
}

// selfPointerBomb 构造自指压缩指针：偏移 12 处的名字指向偏移 12 自身。
func selfPointerBomb() []byte {
	return append(dnsHeader(1, 0),
		0xC0, 0x0C, // NAME = 指向偏移 12（即自身）
		0x00, 0x0C, // TYPE = PTR
		0x00, 0x01, // CLASS = IN
		0x00, 0x00, 0x00, 0x0A, // TTL
		0x00, 0x02, // RDLENGTH
		0xC0, 0x0C, // RDATA 亦指向自身
	)
}

// mutualPointerBomb 构造双指针互指成环：12 指向 14，14 指向 12。
func mutualPointerBomb() []byte {
	return append(dnsHeader(1, 0),
		0xC0, 0x0E, // 偏移 12 → 14
		0xC0, 0x0C, // 偏移 14 → 12
		0x00, 0x0C, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x0A,
		0x00, 0x02, 0xC0, 0x0C,
	)
}

// startRawResponder 起一个只回固定字节的 UDP 服务端，用于投递恶意报文。
func startRawResponder(t *testing.T, reply []byte, times int) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			_, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if strings.Contains(err.Error(), "closed") {
					return
				}
				continue
			}
			for i := 0; i < times; i++ {
				if _, err := conn.WriteToUDP(reply, addr); err != nil {
					return
				}
			}
		}
	}()
	t.Cleanup(func() { _ = conn.Close(); <-done })
	return port
}

// TestS3CompressionPointerLoops 覆盖 §9.5-S3：
// 压缩指针自指或成环时，解析不得陷入死循环或栈溢出。
//
// 此前该项标注为「依赖解析库自身防护，未独立验证」。
// 这里手工构造两种环并投递到真实套接字上，把防护固化为断言——
// 将来若更换解析库，本用例会立刻暴露风险。
func TestS3CompressionPointerLoops(t *testing.T) {
	bombs := []struct {
		name string
		pkt  []byte
	}{
		{"自指指针", selfPointerBomb()},
		{"双指针互指成环", mutualPointerBomb()},
	}
	for _, b := range bombs {
		t.Run(b.name, func(t *testing.T) {
			// 其一：解析层必须拒绝且不 panic、不挂死。
			errCh := make(chan error, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						errCh <- errors.New("解析发生 panic")
					}
				}()
				m := new(dns.Msg)
				errCh <- m.Unpack(b.pkt)
			}()
			select {
			case err := <-errCh:
				if err == nil {
					t.Error("§9.5-S3：压缩指针环被当作合法报文接受")
				} else if strings.Contains(err.Error(), "panic") {
					t.Errorf("§9.5-S3：%v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("§9.5-S3：解析超过 5 秒未返回，存在死循环")
			}

			// 其二：经真实套接字投递时，整轮探测必须正常收尾。
			port := startRawResponder(t, b.pkt, 1)
			orig := mdnsPort
			mdnsPort = port
			t.Cleanup(func() { mdnsPort = orig })

			fin := make(chan int, 1)
			go func() {
				msgs, _ := probeUnicast(context.Background(),
					net.ParseIP("127.0.0.1"), 500*time.Millisecond)
				fin <- len(msgs)
			}()
			select {
			case n := <-fin:
				if n != 0 {
					t.Errorf("恶意报文被收下 %d 条，应全部丢弃", n)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("§9.5-S3：探测被恶意报文卡死")
			}
		})
	}
}

// TestS4InflatedRecordCount 覆盖 §9.5-S4 的第一个方向：
// 报文声明海量记录但实际为空时，不得按声明值预分配内存。
func TestS4InflatedRecordCount(t *testing.T) {
	// 声明回答区与附加区各 65535 条，报文体却只有 12 字节的头。
	pkt := dnsHeader(0xFFFF, 0xFFFF)

	const rounds = 200
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < rounds; i++ {
		m := new(dns.Msg)
		_ = m.Unpack(pkt)
	}
	runtime.ReadMemStats(&after)

	perParse := (after.TotalAlloc - before.TotalAlloc) / rounds
	// 若按声明值预分配，单次解析需为 13 万条记录留空间，量级在数 MB。
	// 阈值取 64 KB，留足正常解析的余量。
	if perParse > 64*1024 {
		t.Errorf("§9.5-S4：单次解析平均分配 %d 字节，疑似按报文声明值预分配", perParse)
	}
}

// TestS4PacketFloodIsCapped 覆盖 §9.5-S4 的第二个方向：
// 单个目标持续灌包时，收包数量必须被 maxMsgPerIP 截断。
func TestS4PacketFloodIsCapped(t *testing.T) {
	// 回一个结构合法但内容为空的应答，每次查询灌 150 个。
	empty := new(dns.Msg)
	empty.Response = true
	raw, err := empty.Pack()
	if err != nil {
		t.Fatal(err)
	}
	// 单次查询即灌 400 个，确保超过 maxMsgPerIP 的 256，
	// 让上限真正被触发而非侥幸未达。
	port := startRawResponder(t, raw, 400)
	orig := mdnsPort
	mdnsPort = port
	t.Cleanup(func() { mdnsPort = orig })

	msgs, err := probeUnicast(context.Background(), net.ParseIP("127.0.0.1"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) > maxMsgPerIP {
		t.Errorf("§9.5-S4：收下 %d 条报文，超过上限 %d", len(msgs), maxMsgPerIP)
	}
	if len(msgs) == 0 {
		t.Error("上限生效的同时不应一条都不收")
	}
	// 必须恰好被截在上限处，否则说明上限未生效。
	if len(msgs) != maxMsgPerIP {
		t.Errorf("§9.5-S4：灌包 400 条却收下 %d 条，期望被截断在 %d",
			len(msgs), maxMsgPerIP)
	}
}

// TestS4OversizedDatagram 覆盖 §9.5-S4 的第三个方向：
// 超过 maxPacket 的巨型数据包只被读入固定缓冲，不得按实际长度分配。
func TestS4OversizedDatagram(t *testing.T) {
	// 构造一个 60 KB 的数据包，远超 maxPacket 的 9000 字节。
	oversized := make([]byte, 60*1024)
	copy(oversized, dnsHeader(1, 0))
	port := startRawResponder(t, oversized, 1)
	orig := mdnsPort
	mdnsPort = port
	t.Cleanup(func() { mdnsPort = orig })

	// 只要不 panic、不挂死即达标；截断后的报文解析失败被跳过。
	msgs, err := probeUnicast(context.Background(), net.ParseIP("127.0.0.1"), 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.msg == nil {
			t.Error("截断的巨型包被当作有效响应收下")
		}
	}
}

// ═══════════════ C4 隔离性 / C7 性能门限 / S7 活动面 ═══════════════

// disableMulticast 关掉组播通道，避免其干扰本组用例的计时与计数。
func disableMulticast(t *testing.T) {
	t.Helper()
	orig := listenUDP
	t.Cleanup(func() { listenUDP = orig })
	listenUDP = func(string, *net.UDPAddr) (*net.UDPConn, error) {
		return nil, errors.New("本用例禁用组播通道")
	}
}

// TestC4SlowTargetDoesNotBlockOthers 覆盖 §9.6-C4：
// 一个地址卡到超时，不得影响其余地址按时完成。
//
// 此前该项标注为「未构造黑洞地址专项验证」。这里在同一次扫描里
// 放两类目标：一个正常应答，一个只答元查询、对后续查询沉默
// （因此耗满整个预算）。若实现把两者串行化，总耗时会翻倍。
func TestC4SlowTargetDoesNotBlockOthers(t *testing.T) {
	disableMulticast(t)

	fast := startFakeResponder(t, nasResponder())
	stall := nasResponder()
	stall.answerOnlyMeta = true
	startFakeResponder(t, stall)

	// .1 → 正常应答，.2 → 滞留
	routeByLastOctet(t, map[byte]int{1: fast.port, 2: stall.port}, 1)

	const budget = 900 * time.Millisecond
	_, ipnet, err := net.ParseCIDR("127.0.0.0/30") // 得到 .1 与 .2
	if err != nil {
		t.Fatal(err)
	}
	targets, err := expandCIDR(ipnet)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Net: ipnet, PortMin: 1, PortMax: 65535,
		Timeout: budget, Concurrency: 2}

	var warn bytes.Buffer
	start := time.Now()
	groups := probeAll(context.Background(), cfg, targets, &warn)
	elapsed := time.Since(start)

	// 两个目标并行执行，总耗时应约等于单个预算；
	// 若被串行化则接近两倍。阈值取 1.6 倍以容忍调度抖动。
	if elapsed > budget*8/5 {
		t.Errorf("§9.6-C4：总耗时 %v，单目标预算 %v，滞留目标拖慢了整体",
			elapsed, budget)
	}
	// 正常目标的数据必须照常拿到。
	if len(groups) == 0 {
		t.Fatal("正常应答的目标未产出任何响应")
	}
	hosts := aggregate(groups, cfg)
	if len(hosts) == 0 {
		t.Fatal("未聚合出任何设备")
	}
	if !strings.Contains(renderAll(hosts), "5000/tcp qdiscover") {
		t.Error("§9.6-C4：正常目标的服务数据丢失，被滞留目标影响")
	}
}

// TestC7ConcurrencyDoesNotSerialize 为 §9.6-C7 提供一个可复现的性能门限。
//
// 真实局域网的耗时依赖环境，无法作为断言。这里把全部 254 个目标
// 导向本地一个只收不回的黑洞端口：耗时只由并发模型决定，与网络无关，
// 因此可在任意机器上复现。
//
// 若 worker pool 退化为串行，耗时会是 254 × 早退开销，量级在数十秒。
func TestC7ConcurrencyDoesNotSerialize(t *testing.T) {
	disableMulticast(t)
	blackhole := startRawResponder(t, nil, 0) // 只收不回
	routeByLastOctet(t, nil, blackhole)

	const budget = 300 * time.Millisecond
	_, ipnet, err := net.ParseCIDR("127.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	targets, err := expandCIDR(ipnet)
	if err != nil {
		t.Fatal(err)
	}
	if targets.Len() != 254 {
		t.Fatalf("目标数 %d，期望 254", targets.Len())
	}
	cfg := Config{Net: ipnet, PortMin: 1, PortMax: 65535,
		Timeout: budget, Concurrency: 256}

	var warn bytes.Buffer
	start := time.Now()
	probeAll(context.Background(), cfg, targets, &warn)
	elapsed := time.Since(start)

	// 254 个目标一批打完，各自早退于预算的 1/3，总耗时应在百毫秒量级。
	// 门限取 2 秒：既远低于串行化的数十秒，又留足 CI 机器的余量。
	if elapsed > 2*time.Second {
		t.Errorf("§9.6-C7：254 个目标耗时 %v，并发模型疑似退化为串行", elapsed)
	}
	t.Logf("254 个黑洞目标耗时 %v（预算 %v，门限 2s）", elapsed, budget)
}

// TestS7OnlyTargetsInsideCIDR 覆盖 §9.5-S7：
// 仅向 --cidr 指定范围发包，不主动出网。
//
// 此前该项标注为「需抓包验证」。改用记录所有 dial 目标的方式——
// 这比抓包更直接：抓包只能看到实际发出的流量，
// 而这里断言的是程序**试图**联系的每一个地址。
func TestS7OnlyTargetsInsideCIDR(t *testing.T) {
	disableMulticast(t)

	var (
		mu       sync.Mutex
		attempts []net.IP
	)
	orig := dialUDP
	t.Cleanup(func() { dialUDP = orig })
	blackhole := startRawResponder(t, nil, 0)
	dialUDP = func(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
		mu.Lock()
		attempts = append(attempts, append(net.IP(nil), raddr.IP...))
		mu.Unlock()
		return orig(network, laddr, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: blackhole})
	}

	const cidr = "192.168.77.0/29"
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := expandCIDR(ipnet)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Net: ipnet, PortMin: 1, PortMax: 65535,
		Timeout: 200 * time.Millisecond, Concurrency: 8}

	var warn bytes.Buffer
	probeAll(context.Background(), cfg, targets, &warn)

	mu.Lock()
	defer mu.Unlock()
	if len(attempts) == 0 {
		t.Fatal("未记录到任何 dial 尝试，用例失效")
	}
	for _, ip := range attempts {
		if !ipnet.Contains(ip) {
			t.Errorf("§9.5-S7：程序试图联系 %s，超出指定网段 %s", ip, cidr)
		}
	}
	// 目标数须与网段展开结果一致：不多打一个，也不漏打一个。
	if len(attempts) != targets.Len() {
		t.Errorf("dial 尝试 %d 次，网段内有 %d 个地址，数量应一致",
			len(attempts), targets.Len())
	}
	t.Logf("%d 次 dial 尝试全部落在 %s 内", len(attempts), cidr)
}

// TestS7MulticastDestinationIsLinkLocal 补齐 §9.5-S7 的另一半：
// 除网段内地址外，唯一的发包目标是链路本地组播组。
// 该地址按定义不会被路由器转发，因此不存在「主动出网」。
func TestS7MulticastDestinationIsLinkLocal(t *testing.T) {
	if got := mdnsGroupV4.String(); got != "224.0.0.251" {
		t.Errorf("组播目标为 %s，期望标准的 224.0.0.251", got)
	}
	// 224.0.0.0/24 是链路本地组播段，TTL 为 1，不跨路由器。
	_, linkLocal, err := net.ParseCIDR("224.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if !linkLocal.Contains(mdnsGroupV4) {
		t.Errorf("§9.5-S7：组播目标 %s 不在链路本地段内，存在出网风险", mdnsGroupV4)
	}
	if mdnsPort != 5353 {
		t.Errorf("协议端口为 %d，期望 5353", mdnsPort)
	}
}
