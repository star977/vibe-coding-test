package main

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

const (
	mdnsPort  = 5353
	metaQuery = "_services._dns-sd._udp.local."

	// §9.5-S4 内存放大防护：单个报文读取上限与单目标报文条数上限。
	// RFC 6762 允许的最大报文约 9000 字节，超出部分丢弃而非按声明值分配。
	maxPacket   = 9000
	maxMsgPerIP = 256
)

var mdnsGroupV4 = net.IPv4(224, 0, 0, 251)

// 套接字创建提取为变量，供测试注入：
//   - listenUDP：注入失败以覆盖 §9.4-E9 的组播降级路径
//   - dialUDP：包一层计数器以实测 §9.6-C2 的并发上限是否真的生效
var (
	listenUDP = net.ListenUDP
	dialUDP   = net.DialUDP
)

// recvMsg 是一条已解包的响应及其来源地址。
// 组播通道下来源各不相同，故必须随报文一起记录（§4.3 节点 ③a）。
type recvMsg struct {
	src net.IP
	msg *dns.Msg
}

// prober 封装一条探测通道。单播与组播共用同一套收发逻辑，
// 唯一差别是目的地址与源地址过滤方式（§4.3 节点 ③a / ③b）。
type prober struct {
	conn *net.UDPConn
	dst  *net.UDPAddr // 单播为 nil（socket 已 connect）；组播为组地址
}

// newUnicastProber 建立指向单个目标的通道。
//
// 使用 DialUDP 而非 ListenUDP 是有意为之：已连接的 UDP socket 由内核
// 只投递来自该目标地址的报文，等于免费满足 §9.5-S1（响应源伪造防护），
// 无需在用户态再写一遍源地址校验。
func newUnicastProber(dst net.IP, budget time.Duration) (*prober, error) {
	conn, err := dialUDP("udp4", nil, &net.UDPAddr{IP: dst, Port: mdnsPort})
	if err != nil {
		return nil, err
	}
	return &prober{conn: conn}, nil
}

// newMulticastProber 建立组播兜底通道（§4.3 节点 ③a）。
//
// 从临时端口向组地址发问即可：按 RFC 6762 §6.7，源端口非 5353 的查询
// 会得到直接发回本端口的单播响应，因此无需加入组播组。
func newMulticastProber() (*prober, error) {
	conn, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	return &prober{conn: conn, dst: &net.UDPAddr{IP: mdnsGroupV4, Port: mdnsPort}}, nil
}

func (p *prober) Close() error { return p.conn.Close() }

func (p *prober) send(name string, qtype uint16) error {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = false
	m.Question = []dns.Question{{Name: dns.Fqdn(name), Qtype: qtype, Qclass: dns.ClassINET}}

	raw, err := m.Pack()
	if err != nil {
		return err
	}
	if p.dst == nil {
		_, err = p.conn.Write(raw)
	} else {
		_, err = p.conn.WriteToUDP(raw, p.dst)
	}
	return err
}

// collect 持续收包直到截止时刻。
// §4.3 节点 ③b 边界：同一地址可能返回多个报文，不能收到第一个就停。
func (p *prober) collect(until time.Time, out []recvMsg) []recvMsg {
	buf := make([]byte, maxPacket)
	for len(out) < maxMsgPerIP {
		if err := p.conn.SetReadDeadline(until); err != nil {
			return out
		}
		n, addr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return out // 超时或出错即收尾，属正常路径
		}
		m := new(dns.Msg)
		// §9.4-E3：畸形报文跳过即可，不得 panic、不得中断本地址其余收包。
		if err := m.Unpack(buf[:n]); err != nil {
			continue
		}
		out = append(out, recvMsg{src: append(net.IP(nil), addr.IP...), msg: m})
	}
	return out
}

// run 执行 DNS-SD 三段式追查。
// 规格：DESIGN.md §4.3 节点 ③b 的处理列，配合 §8.3「先榨干附加区」。
//
// budget 是本通道的总时间预算，非单次等待（§4.1）。
func (p *prober) run(ctx context.Context, budget time.Duration) []recvMsg {
	// §9.6-C5 取消传播：ctx 取消时关闭连接，使阻塞中的读立即返回。
	// 若仅靠读超时，用户按下 Ctrl-C 后仍要等满整个预算才退出——
	// --timeout 设成 30s 时就是干等 30 秒。
	defer context.AfterFunc(ctx, func() { _ = p.conn.Close() })()

	start := time.Now()
	phase := budget / 3
	var all []recvMsg

	// Q1：问「你有哪些服务类型」
	if p.send(metaQuery, dns.TypePTR) != nil {
		return nil
	}
	all = p.collect(start.Add(phase), all)

	// 无人应答则立即收尾。/24 里绝大多数地址是空的，
	// 这一步把死地址的开销从整个预算压到 1/3，是 §9.6-C7 达标的关键。
	if len(all) == 0 && p.dst == nil {
		return nil
	}

	// Q2：对每个服务类型问「有哪些实例」
	for _, t := range collectPTRTargets(all, metaQuery) {
		_ = p.send(t, dns.TypePTR)
	}
	if ctx.Err() != nil {
		return all
	}
	all = p.collect(start.Add(2*phase), all)

	// Q3：只对仍缺定位记录或描述记录的实例补问（§8.3）。
	for _, inst := range instancesMissingDetail(all) {
		_ = p.send(inst, dns.TypeSRV)
		_ = p.send(inst, dns.TypeTXT)
	}
	if ctx.Err() != nil {
		return all
	}
	all = p.collect(start.Add(budget), all)

	return all
}

// probeUnicast 是节点 ③b 的入口。
// §9.4-E2：目标不可达或超时一律静默跳过，返回空切片。
func probeUnicast(ctx context.Context, dst net.IP, budget time.Duration) []recvMsg {
	p, err := newUnicastProber(dst, budget)
	if err != nil {
		return nil
	}
	defer p.Close()
	return p.run(ctx, budget)
}

// probeMulticast 是节点 ③a 的入口。
// §4.3 节点 ③a 失败列：组播不可用时返回 nil，由调用方降级为纯单播。
func probeMulticast(ctx context.Context, budget time.Duration) ([]recvMsg, error) {
	p, err := newMulticastProber()
	if err != nil {
		return nil, err
	}
	defer p.Close()
	return p.run(ctx, budget), nil
}
