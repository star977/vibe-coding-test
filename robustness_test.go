package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
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
