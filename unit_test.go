package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ═══════════════ 名称转义还原（§7.3-①、§9.5-S2、§9.3-B18）═══════════════

func TestUnescapeName(t *testing.T) {
	cases := []struct {
		spec, in, want string
	}{
		{"无转义原样返回", "slw-nas", "slw-nas"},
		{"反斜杠加空格", `slw-nas\ [24:5e]`, "slw-nas [24:5e]"},
		{"三位十进制空格", `a\032b`, "a b"},
		{"转义的点", `a\.b`, "a.b"},
		{"转义的反斜杠", `a\\b`, `a\b`},
		{"UTF-8 须还原，否则中文乱码", `\228\184\173文`, "中文"},
		{"控制字符保持转义态", `evil\010fake`, `evil\010fake`},
		{"回车保持转义态", `a\013b`, `a\013b`},
		{"ESC 保持转义态", `a\027[31m`, `a\027[31m`},
		{"DEL 保持转义态", `a\127b`, `a\127b`},
		{"高位字节可还原（\\192 即 0xC0）", `a\192b`, "a\xc0b"},
		{"超出 255 的十进制数保持字面", `a\300b`, `a\300b`},
		{"末尾孤立反斜杠不崩", `abc\`, `abc\`},
		{"空字符串", "", ""},
		{"混合：可还原与不可还原共存", `x\032y\010z`, `x y\010z`},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			if got := unescapeName(c.in); got != c.want {
				t.Errorf("unescapeName(%q) = %q，期望 %q", c.in, got, c.want)
			}
		})
	}
}

func TestIsSafeByte(t *testing.T) {
	// 门槛：>= 0x20 且不等于 0x7f。低于 0x20 是控制字符（§9.5-S2），
	// 高于 0x7f 是 UTF-8 字节，必须放行（§9.3-B18）。
	cases := []struct {
		b    byte
		want bool
		why  string
	}{
		{0x00, false, "NUL"}, {0x09, false, "TAB"}, {0x0a, false, "LF"},
		{0x0d, false, "CR"}, {0x1b, false, "ESC"}, {0x1f, false, "边界下沿"},
		{0x20, true, "空格，边界上沿"}, {0x41, true, "字母"},
		{0x7e, true, "~"}, {0x7f, false, "DEL"},
		{0x80, true, "UTF-8 续字节"}, {0xe4, true, "UTF-8 前导字节"}, {0xff, true, "高位"},
	}
	for _, c := range cases {
		if got := isSafeByte(c.b); got != c.want {
			t.Errorf("isSafeByte(0x%02x) = %v，期望 %v（%s）", c.b, got, c.want, c.why)
		}
	}
}

// ═══════════════ 名称拆解 ═══════════════

func TestSplitInstance(t *testing.T) {
	cases := []struct {
		in, wantInst, wantType string
		wantOK                 bool
	}{
		{"alpha._http._tcp.local.", "alpha", "_http._tcp.local.", true},
		{`a\ b._workstation._tcp.local.`, "a b", "_workstation._tcp.local.", true},
		{"_http._tcp.local.", "", "", false}, // 标签不足四段
		{"local.", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		inst, typ, ok := splitInstance(c.in)
		if ok != c.wantOK {
			t.Errorf("splitInstance(%q) ok = %v，期望 %v", c.in, ok, c.wantOK)
			continue
		}
		if ok && (inst != c.wantInst || typ != c.wantType) {
			t.Errorf("splitInstance(%q) = (%q, %q)，期望 (%q, %q)",
				c.in, inst, typ, c.wantInst, c.wantType)
		}
	}
}

func TestTypeAndProto(t *testing.T) {
	cases := []struct {
		in, wantType, wantProto string
		wantOK                  bool
	}{
		{"_http._tcp.local.", "http", "tcp", true},
		{"_sleep-proxy._udp.local.", "sleep-proxy", "udp", true},
		{"_device-info._tcp.local.", "device-info", "tcp", true},
		{"_tcp.local.", "", "", false}, // 标签不足三段
		{"", "", "", false},
	}
	for _, c := range cases {
		typ, proto, ok := typeAndProto(c.in)
		if ok != c.wantOK {
			t.Errorf("typeAndProto(%q) ok = %v，期望 %v", c.in, ok, c.wantOK)
			continue
		}
		if ok && (typ != c.wantType || proto != c.wantProto) {
			t.Errorf("typeAndProto(%q) = (%q, %q)，期望 (%q, %q)",
				c.in, typ, proto, c.wantType, c.wantProto)
		}
	}
}

func TestAppendUnique(t *testing.T) {
	got := []string{}
	for _, v := range []string{"a", "b", "a", "c", "b"} {
		got = appendUnique(got, v)
	}
	want := []string{"a", "b", "c"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("appendUnique 结果 %v，期望 %v（须去重且保持首次出现顺序）", got, want)
	}
}

// ═══════════════ 排序与过滤 ═══════════════

func TestCompareIP(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"192.168.1.1", "192.168.1.2", -1},
		{"192.168.1.2", "192.168.1.1", 1},
		{"192.168.1.1", "192.168.1.1", 0},
		{"192.168.1.9", "192.168.1.10", -1}, // 须按数值而非字典序
		{"10.0.0.1", "192.168.1.1", -1},
		{"192.168.2.1", "192.168.10.1", -1},
	}
	for _, c := range cases {
		got := compareIP(net.ParseIP(c.a), net.ParseIP(c.b))
		if got != c.want {
			t.Errorf("compareIP(%s, %s) = %d，期望 %d", c.a, c.b, got, c.want)
		}
	}
}

func TestFilterByPort(t *testing.T) {
	in := []Service{
		{Type: "ssh", Port: 22, HasPort: true},
		{Type: "http", Port: 80, HasPort: true},
		{Type: "device-info", HasPort: false}, // 无端口
		{Type: "alt", Port: 8080, HasPort: true},
	}
	cases := []struct {
		spec     string
		min, max uint16
		want     []string
	}{
		{"全范围保留全部", 1, 65535, []string{"ssh", "http", "device-info", "alt"}},
		{"窄范围仅留范围内 + 无端口", 80, 80, []string{"http", "device-info"}},
		{"下边界含端口本身", 22, 22, []string{"ssh", "device-info"}},
		{"范围内无任何有端口服务时仍留无端口服务", 1, 21, []string{"device-info"}},
		{"上边界", 8080, 9000, []string{"device-info", "alt"}},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			got := filterByPort(in, c.min, c.max)
			var names []string
			for _, s := range got {
				names = append(names, s.Type)
			}
			if strings.Join(names, ",") != strings.Join(c.want, ",") {
				t.Errorf("filterByPort(%d-%d) = %v，期望 %v", c.min, c.max, names, c.want)
			}
		})
	}
	// 确认原切片未被就地改写——filterByPort 复用底层数组时极易踩此坑。
	if len(in) != 4 {
		t.Errorf("入参切片被改写，长度变为 %d", len(in))
	}
}

// ═══════════════ 参数构建（§4.3 节点①）═══════════════

func TestBuildConfig(t *testing.T) {
	t.Run("合法输入", func(t *testing.T) {
		cfg, err := buildConfig("192.168.1.0/24", "1-1000", 3*time.Second, 64)
		if err != nil {
			t.Fatalf("意外报错: %v", err)
		}
		if cfg.Net.String() != "192.168.1.0/24" {
			t.Errorf("Net = %v", cfg.Net)
		}
		if cfg.PortMin != 1 || cfg.PortMax != 1000 {
			t.Errorf("端口范围 = %d-%d，期望 1-1000", cfg.PortMin, cfg.PortMax)
		}
		if cfg.Timeout != 3*time.Second || cfg.Concurrency != 64 {
			t.Errorf("Timeout=%v Concurrency=%d", cfg.Timeout, cfg.Concurrency)
		}
	})

	bad := []struct {
		spec, cidr, ports string
		timeout           time.Duration
		conc              int
		wantSubstr        string
	}{
		{"缺 cidr", "", "1-100", time.Second, 1, "--cidr 必填"},
		{"cidr 非法", "abc", "1-100", time.Second, 1, "不是合法网段"},
		{"掩码越界", "192.168.1.0/33", "1-100", time.Second, 1, "不是合法网段"},
		{"端口非法", "192.168.1.0/24", "0-100", time.Second, 1, "--ports"},
		{"超时为零", "192.168.1.0/24", "1-100", 0, 1, "--timeout"},
		{"超时为负", "192.168.1.0/24", "1-100", -time.Second, 1, "--timeout"},
		{"并发为零", "192.168.1.0/24", "1-100", time.Second, 0, "--concurrency"},
		{"并发为负", "192.168.1.0/24", "1-100", time.Second, -5, "--concurrency"},
	}
	for _, c := range bad {
		t.Run(c.spec, func(t *testing.T) {
			_, err := buildConfig(c.cidr, c.ports, c.timeout, c.conc)
			if err == nil {
				t.Fatal("应报错，实际通过")
			}
			// §4.3 节点①失败列：报错须指明是哪个参数。
			if !strings.Contains(err.Error(), c.wantSubstr) {
				t.Errorf("报错 %q 未包含 %q，无法指认出错参数", err, c.wantSubstr)
			}
		})
	}
}

// ═══════════════ 渲染（§4.4 格式规则）═══════════════

// TestRenderHostGolden 用逐字节比对锁定输出格式。
// 格式一旦被无意改动，本用例会立刻失败。
func TestRenderHostGolden(t *testing.T) {
	h := &Host{
		IP:       net.ParseIP("192.168.1.20"),
		IPv4:     "192.168.1.20",
		IPv6:     "fe80::20",
		Hostname: "slw-nas.local",
		PTRTypes: []string{"_workstation._tcp.local.", "_device-info._tcp.local."},
		Services: []Service{
			{Name: "slw-nas [24:5e]", Type: "workstation", Proto: "tcp",
				Port: 9, HasPort: true, TTL: 10},
			{Name: "slw-nas", Type: "device-info", Proto: "tcp",
				HasPort: false, TTL: 10, TXT: []string{"model=Xserve"}},
		},
	}
	want := `services:
9/tcp workstation:
Name=slw-nas [24:5e]
IPv4=192.168.1.20
IPv6=fe80::20
Hostname=slw-nas.local
TTL=10
device-info:
Name=slw-nas
IPv4=192.168.1.20
IPv6=fe80::20
Hostname=slw-nas.local
TTL=10
model=Xserve
answers:
PTR:
_workstation._tcp.local
_device-info._tcp.local
`
	var b strings.Builder
	renderHost(h, &b)
	if got := b.String(); got != want {
		t.Errorf("渲染输出与预期不符。\n--- 实际 ---\n%s\n--- 期望 ---\n%s", got, want)
	}
}

func TestRenderHostOmitsMissingFields(t *testing.T) {
	// §9.3-B17：无 IPv4/IPv6/Hostname 时整行省略，不输出空值。
	h := &Host{
		IP:       net.ParseIP("192.168.1.5"),
		IPv6:     "fe80::5",
		PTRTypes: []string{"_ssh._tcp.local."},
		Services: []Service{{Name: "x", Type: "ssh", Proto: "tcp", Port: 22, HasPort: true, TTL: 10}},
	}
	var b strings.Builder
	renderHost(h, &b)
	out := b.String()
	for _, bad := range []string{"IPv4=\n", "Hostname=\n", "IPv4=<nil>"} {
		if strings.Contains(out, bad) {
			t.Errorf("输出中出现空值行 %q:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "IPv6=fe80::5") {
		t.Errorf("IPv6 行缺失:\n%s", out)
	}
}

// ═══════════════ 记录索引（§4.3 节点④）═══════════════

func TestRecordIndexScansAllSections(t *testing.T) {
	// §8.3：回答区、附加区、授权区须一视同仁。
	// 设备常把定位记录与描述记录塞在附加区随 PTR 返回。
	hdr := func(n string, rt uint16) dns.RR_Header {
		return dns.RR_Header{Name: n, Rrtype: rt, Class: dns.ClassINET, Ttl: 42}
	}
	m := new(dns.Msg)
	m.Answer = []dns.RR{&dns.PTR{Hdr: hdr("_http._tcp.local.", dns.TypePTR), Ptr: "a._http._tcp.local."}}
	m.Extra = []dns.RR{&dns.SRV{Hdr: hdr("a._http._tcp.local.", dns.TypeSRV), Port: 80, Target: "h.local."}}
	m.Ns = []dns.RR{&dns.TXT{Hdr: hdr("a._http._tcp.local.", dns.TypeTXT), Txt: []string{"k=v"}}}

	ri := newRecordIndex()
	ri.index([]recvMsg{{src: net.ParseIP("1.2.3.4"), msg: m}})

	if got := ri.ptr["_http._tcp.local."]; len(got) != 1 {
		t.Errorf("回答区的 PTR 未被索引: %v", got)
	}
	if ri.srv["a._http._tcp.local."] == nil {
		t.Error("附加区的 SRV 未被索引")
	}
	if got := ri.txt["a._http._tcp.local."]; len(got) != 1 || got[0] != "k=v" {
		t.Errorf("授权区的 TXT 未被索引: %v", got)
	}
	if ri.ttl["a._http._tcp.local."] != 42 {
		t.Errorf("TTL = %d，期望 42", ri.ttl["a._http._tcp.local."])
	}
	// ptrOwners 记录首次出现顺序，是输出确定性的基础（§9.6-C6）。
	if len(ri.ptrOwners) != 1 || ri.ptrOwners[0] != "_http._tcp.local." {
		t.Errorf("ptrOwners = %v", ri.ptrOwners)
	}
}

func TestInstancesMissingDetail(t *testing.T) {
	hdr := func(n string, rt uint16) dns.RR_Header {
		return dns.RR_Header{Name: n, Rrtype: rt, Class: dns.ClassINET, Ttl: 10}
	}
	m := new(dns.Msg)
	m.Answer = []dns.RR{
		// full：SRV 与 TXT 齐备，无需补问
		&dns.PTR{Hdr: hdr("_a._tcp.local.", dns.TypePTR), Ptr: "full._a._tcp.local."},
		// nosrv：缺 SRV
		&dns.PTR{Hdr: hdr("_b._tcp.local.", dns.TypePTR), Ptr: "nosrv._b._tcp.local."},
		// 元查询的目标是服务类型而非实例，不应被当作待补问对象
		&dns.PTR{Hdr: hdr(metaQuery, dns.TypePTR), Ptr: "_a._tcp.local."},
	}
	m.Extra = []dns.RR{
		&dns.SRV{Hdr: hdr("full._a._tcp.local.", dns.TypeSRV), Port: 1, Target: "h.local."},
		&dns.TXT{Hdr: hdr("full._a._tcp.local.", dns.TypeTXT), Txt: []string{"x=1"}},
		&dns.TXT{Hdr: hdr("nosrv._b._tcp.local.", dns.TypeTXT), Txt: []string{"y=2"}},
	}
	got := instancesMissingDetail([]recvMsg{{src: net.ParseIP("1.2.3.4"), msg: m}})

	joined := strings.Join(got, ",")
	if strings.Contains(joined, "full.") {
		t.Errorf("信息齐备的实例不应补问: %v", got)
	}
	if !strings.Contains(joined, "nosrv.") {
		t.Errorf("缺 SRV 的实例应补问: %v", got)
	}
	if strings.Contains(joined, "_a._tcp.local.") && !strings.Contains(joined, ".") {
		t.Errorf("服务类型被误当作实例: %v", got)
	}
}

func TestCollectPTRTargets(t *testing.T) {
	hdr := dns.RR_Header{Name: metaQuery, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10}
	m := new(dns.Msg)
	m.Answer = []dns.RR{
		&dns.PTR{Hdr: hdr, Ptr: "_http._tcp.local."},
		&dns.PTR{Hdr: hdr, Ptr: "_ssh._tcp.local."},
		&dns.PTR{Hdr: hdr, Ptr: "_http._tcp.local."}, // 重复项
	}
	got := collectPTRTargets([]recvMsg{{src: net.ParseIP("1.2.3.4"), msg: m}}, metaQuery)
	if len(got) != 2 || got[0] != "_http._tcp.local." || got[1] != "_ssh._tcp.local." {
		t.Errorf("collectPTRTargets = %v，期望去重且保序的两项", got)
	}
	// 不存在的所有者应返回空，而非 panic。
	if got := collectPTRTargets(nil, "_nope._tcp.local."); len(got) != 0 {
		t.Errorf("空输入应返回空，实际 %v", got)
	}
}

// ═══════════════ 并发裁剪提示 ═══════════════

func TestEffectiveConcurrencyWarnsOnce(t *testing.T) {
	var warn bytes.Buffer
	effectiveConcurrency(99999, 100, &warn)
	if n := strings.Count(warn.String(), "已截断"); n != 1 {
		t.Errorf("截断提示出现 %d 次，应恰好 1 次", n)
	}
}
