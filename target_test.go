package main

import (
	"net"
	"testing"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("解析 %q 失败: %v", s, err)
	}
	return n
}

// TestExpandCIDRBoundaries 覆盖 §9.3-B1/B2/B3 的网段展开边界。
func TestExpandCIDRBoundaries(t *testing.T) {
	cases := []struct {
		spec, cidr string
		want       []string
	}{
		{"B1 /32 应返回该地址本身，不可为空", "192.168.1.5/32",
			[]string{"192.168.1.5"}},
		{"B2 /31 应返回两个地址，点对点网段不剔除", "192.168.1.4/31",
			[]string{"192.168.1.4", "192.168.1.5"}},
		{"B3 /30 应剔除网络地址与广播地址", "192.168.1.0/30",
			[]string{"192.168.1.1", "192.168.1.2"}},
		{"B3 /29 应剔除首末两个地址", "192.168.1.0/29",
			[]string{"192.168.1.1", "192.168.1.2", "192.168.1.3",
				"192.168.1.4", "192.168.1.5", "192.168.1.6"}},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			r, err := expandCIDR(mustCIDR(t, c.cidr))
			if err != nil {
				t.Fatal(err)
			}
			got := r.Slice()
			if len(got) != len(c.want) {
				t.Fatalf("地址数 %d，期望 %d（实际 %v）", len(got), len(c.want), got)
			}
			for i, w := range c.want {
				if got[i].String() != w {
					t.Errorf("第 %d 个地址为 %s，期望 %s", i, got[i], w)
				}
			}
		})
	}
}

// TestExpandCIDRCount 校验 /24 的地址数，这是最常用的规模。
func TestExpandCIDRCount(t *testing.T) {
	r, err := expandCIDR(mustCIDR(t, "192.168.1.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != 254 {
		t.Errorf("/24 地址数为 %d，期望 254（应剔除 .0 与 .255）", r.Len())
	}
}

// TestLargeCIDRIsConstantMemory 覆盖 §9.3-B4：
// 超大网段不得一次性展开进内存。
//
// 改为按需生成前，/12 网段实测占用 29.4 MB，/8 推算约 470 MB。
func TestLargeCIDRIsConstantMemory(t *testing.T) {
	n := mustCIDR(t, "10.0.0.0/8")
	r, err := expandCIDR(n)
	if err != nil {
		t.Fatal(err)
	}
	const want = 1<<24 - 2 // 2^24 减去网络地址与广播地址
	if r.Len() != want {
		t.Errorf("/8 地址数为 %d，期望 %d", r.Len(), want)
	}
	// 分配次数必须与网段大小无关。
	allocs := testing.AllocsPerRun(20, func() {
		_, _ = expandCIDR(n)
	})
	if allocs > 4 {
		t.Errorf("§9.3-B4：expandCIDR 分配 %v 次，应为常量级而非随网段增长", allocs)
	}
}

// TestExpandCIDRRejectsIPv6 覆盖 §9.3-B7：
// IPv6 网段必须明确拒绝，不得静默返回空。
func TestExpandCIDRRejectsIPv6(t *testing.T) {
	r, err := expandCIDR(mustCIDR(t, "fe80::/64"))
	if err == nil {
		t.Fatal("IPv6 网段应返回明确错误，而非静默通过")
	}
	if r.Len() != 1 { // 零值 ipRange 的 Len 为 1，此处仅确认未产出真实地址
		t.Logf("零值区间 Len=%d（调用方必须先检查 error）", r.Len())
	}
}

// TestParsePortRange 覆盖 §9.3-B8~B12 的端口范围解析。
func TestParsePortRange(t *testing.T) {
	ok := []struct {
		in       string
		min, max uint16
	}{
		{"1-65535", 1, 65535},
		{"80-80", 80, 80},
		{"7000", 7000, 7000},
		{" 100 - 200 ", 100, 200},
	}
	for _, c := range ok {
		min, max, err := parsePortRange(c.in)
		if err != nil {
			t.Errorf("parsePortRange(%q) 意外报错: %v", c.in, err)
			continue
		}
		if min != c.min || max != c.max {
			t.Errorf("parsePortRange(%q) = %d-%d，期望 %d-%d", c.in, min, max, c.min, c.max)
		}
	}

	bad := []struct{ spec, in string }{
		{"B9 下界大于上界", "100-50"},
		{"B10 端口 0 非法", "0-100"},
		{"B11 超出 65535", "1-70000"},
		{"B12 非整数", "abc"},
		{"B12 空值", ""},
		{"上界非整数", "80-xyz"},
		{"负数", "-5-10"},
	}
	for _, c := range bad {
		if _, _, err := parsePortRange(c.in); err == nil {
			t.Errorf("%s：parsePortRange(%q) 应报错，实际通过", c.spec, c.in)
		}
	}
}
