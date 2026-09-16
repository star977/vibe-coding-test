package main

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// fakeSvc 描述一个伪造的服务。port 为 0 表示该服务无定位记录，
// 用于覆盖 device-info 这类无端口服务（§4.4、§4.3 节点⑤）。
type fakeSvc struct {
	typ      string
	instance string
	port     uint16
	txt      []string
}

// fakeDevice 合成一台设备的完整响应，经真实的打包/解包往返，
// 以确保测试走的是与线上完全相同的解析路径（含转义行为）。
func fakeDevice(t *testing.T, ip, hostname, v6 string, svcs []fakeSvc) []recvMsg {
	t.Helper()
	m := new(dns.Msg)
	h := func(name string, rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: 10}
	}

	for _, s := range svcs {
		svcType := "_" + s.typ + "._tcp.local."
		inst := s.instance + "." + svcType

		m.Answer = append(m.Answer,
			&dns.PTR{Hdr: h(metaQuery, dns.TypePTR), Ptr: svcType},
			&dns.PTR{Hdr: h(svcType, dns.TypePTR), Ptr: inst},
		)
		if s.port != 0 {
			m.Extra = append(m.Extra, &dns.SRV{
				Hdr: h(inst, dns.TypeSRV), Port: s.port, Target: hostname,
			})
		}
		if len(s.txt) > 0 {
			m.Extra = append(m.Extra, &dns.TXT{Hdr: h(inst, dns.TypeTXT), Txt: s.txt})
		}
	}
	m.Extra = append(m.Extra,
		&dns.A{Hdr: h(hostname, dns.TypeA), A: net.ParseIP(ip)},
		&dns.AAAA{Hdr: h(hostname, dns.TypeAAAA), AAAA: net.ParseIP(v6)},
	)

	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("合成响应打包失败: %v", err)
	}
	got := new(dns.Msg)
	if err := got.Unpack(wire); err != nil {
		t.Fatalf("合成响应解包失败: %v", err)
	}
	return []recvMsg{{src: net.ParseIP(ip), msg: got}}
}

func testConfig(t *testing.T, cidr string, min, max uint16) Config {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return Config{Net: n, PortMin: min, PortMax: max}
}

// 三台设备，故意乱序喂入，覆盖 §9.6-C6 的主机间排序。
func threeDevices(t *testing.T) map[string][]recvMsg {
	t.Helper()
	return map[string][]recvMsg{
		"192.168.1.30": fakeDevice(t, "192.168.1.30", "gamma.local.", "fe80::30", []fakeSvc{
			{typ: "ssh", instance: "gamma", port: 22},
		}),
		"192.168.1.10": fakeDevice(t, "192.168.1.10", "alpha.local.", "fe80::10", []fakeSvc{
			// 实例名含空格，覆盖 §7.3-① 转义还原
			{typ: "workstation", instance: "alpha [24:5e:be:69:a3:13]", port: 9},
			// TXT 覆盖：值含逗号(B19)、值含等号(§7.3-③)、无等号项(§7.3-④)
			{typ: "qdiscover", instance: "alpha", port: 5000,
				txt: []string{"model=TS-X64,rev2", "pk=AbCd==", "flagonly", "fwVer=5.2.9"}},
			// 无端口服务，覆盖 §4.4 与节点⑤的保留规则
			{typ: "device-info", instance: "alpha", port: 0, txt: []string{"model=Xserve"}},
			// 空 TXT，覆盖 §7.3-⑤ 不产生空行
			{typ: "smb", instance: "alpha", port: 445},
		}),
		"192.168.1.20": fakeDevice(t, "192.168.1.20", "beta.local.", "fe80::20", []fakeSvc{
			{typ: "http", instance: "beta", port: 8080, txt: []string{"path=/"}},
		}),
	}
}

func TestMultiHost(t *testing.T) {
	hosts := aggregate(threeDevices(t), testConfig(t, "192.168.1.0/24", 1, 65535))

	if len(hosts) != 3 {
		t.Fatalf("期望 3 台设备，实际 %d 台", len(hosts))
	}
	// §9.6-C6：主机之间必须按 IP 升序，与喂入顺序无关。
	want := []string{"192.168.1.10", "192.168.1.20", "192.168.1.30"}
	for i, w := range want {
		if got := hosts[i].IP.String(); got != w {
			t.Errorf("第 %d 台主机应为 %s，实际 %s", i, w, got)
		}
	}
	// 多主机渲染应产出多个区块。
	out := renderAll(hosts)
	if n := strings.Count(out, "services:\n"); n != 3 {
		t.Errorf("期望 3 个 services 区块，实际 %d 个", n)
	}
	if n := strings.Count(out, "answers:\n"); n != 3 {
		t.Errorf("期望 3 个 answers 区块，实际 %d 个", n)
	}
}

func TestOutputDetails(t *testing.T) {
	hosts := aggregate(threeDevices(t), testConfig(t, "192.168.1.0/24", 1, 65535))
	out := renderAll(hosts)

	cases := []struct {
		spec, want string
	}{
		{"§7.3-① 空格转义已还原", "Name=alpha [24:5e:be:69:a3:13]"},
		{"§4.4 无端口服务不带端口前缀", "\ndevice-info:\n"},
		{"§4.4 有端口服务格式正确", "\n5000/tcp qdiscover:\n"},
		{"§7.3-③ 值含等号未被截断", "pk=AbCd=="},
		{"§7.3-④ 无等号项保留", "flagonly"},
		{"§9.3-B19 值含逗号原样保留", "model=TS-X64,rev2"},
		{"§7.2 IPv6 正常输出", "IPv6=fe80::20"},
	}
	for _, c := range cases {
		if !strings.Contains(out, c.want) {
			t.Errorf("%s：输出中未找到 %q", c.spec, c.want)
		}
	}
	// §7.3-⑤：无 TXT 的服务条目下不得出现空行。
	if strings.Contains(out, "\n\n") {
		t.Error("§7.3-⑤：输出中出现了空行")
	}
	// §9.6-C6：同一主机内服务顺序须与服务类型清单一致，不得排序。
	// alpha 的声明顺序为 workstation(9) → qdiscover(5000) → device-info(无) → smb(445)。
	order := []string{"workstation:", "qdiscover:", "device-info:", "smb:"}
	pos := -1
	for _, o := range order {
		i := strings.Index(out, o)
		if i < 0 {
			t.Fatalf("输出中缺少 %s", o)
		}
		if i < pos {
			t.Errorf("§9.6-C6：服务顺序被打乱，%s 出现位置早于前一项", o)
		}
		pos = i
	}
}

// §4.3 节点⑤关键决策：无端口服务不参与端口过滤，一律保留。
func TestPortFilterKeepsPortlessService(t *testing.T) {
	// 端口范围只留 5000，应滤掉 9/445，但必须保住无端口的 device-info。
	hosts := aggregate(threeDevices(t), testConfig(t, "192.168.1.0/24", 5000, 5000))
	out := renderAll(hosts)

	if strings.Contains(out, "9/tcp workstation") || strings.Contains(out, "445/tcp smb") {
		t.Error("范围外的有端口服务未被滤除")
	}
	if !strings.Contains(out, "\ndevice-info:\n") {
		t.Error("§4.3 节点⑤：无端口服务被误滤，型号信息会因此丢失")
	}
	if !strings.Contains(out, "5000/tcp qdiscover") {
		t.Error("范围内的服务被误滤")
	}
}

// §9.3-B22：组播会带回网段外设备的响应，必须被丢弃。
func TestCIDRFilterDropsOutOfRange(t *testing.T) {
	// /29 覆盖 .16-.23，故仅 .20 在网段内，.10 与 .30 均在范围外。
	hosts := aggregate(threeDevices(t), testConfig(t, "192.168.1.16/29", 1, 65535))
	for _, h := range hosts {
		if h.IP.String() == "192.168.1.10" || h.IP.String() == "192.168.1.30" {
			t.Errorf("网段外设备 %s 未被过滤", h.IP)
		}
	}
	if len(hosts) != 1 {
		t.Errorf("期望仅保留 1 台设备，实际 %d 台", len(hosts))
	}
}

// §9.6-C6 / §7.3-②：重复渲染必须逐字节一致。
// 本用例专门守住 map 遍历顺序随机这一类回归。
func TestDeterministicOutput(t *testing.T) {
	cfg := testConfig(t, "192.168.1.0/24", 1, 65535)
	first := renderAll(aggregate(threeDevices(t), cfg))
	for i := 0; i < 200; i++ {
		if got := renderAll(aggregate(threeDevices(t), cfg)); got != first {
			t.Fatalf("第 %d 次渲染结果与首次不一致，输出存在顺序漂移", i)
		}
	}
}

// §9.5-S2：设备自报内容中的控制字符不得还原成真字符，
// 否则设备可通过换行伪造出整条资产条目。
func TestControlCharactersStayEscaped(t *testing.T) {
	// 名称中嵌入换行（\010）与 ESC（\027）
	if got := unescapeName(`evil\010fake`); strings.ContainsRune(got, '\n') {
		t.Errorf("换行被还原成真换行符，存在输出注入风险: %q", got)
	}
	if got := unescapeName(`evil\027[31m`); strings.ContainsRune(got, 0x1b) {
		t.Errorf("ESC 被还原，终端可被控制序列篡改: %q", got)
	}
	// 两种空格转义写法都要能还原（§7.3-① 实测修正）
	for _, in := range []string{`a\032b`, `a\ b`} {
		if got := unescapeName(in); got != "a b" {
			t.Errorf("unescapeName(%q) = %q，期望 %q", in, got, "a b")
		}
	}
	// §9.3-B18：UTF-8 必须还原，否则中文会变成 \228\184\173
	if got := unescapeName(`\228\184\173文`); got != "中文" {
		t.Errorf("UTF-8 还原失败: %q", got)
	}
}
