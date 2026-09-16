package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ipRange 是待探测的地址区间。
//
// §9.3-B4：按需生成而非一次性展开进内存。实测展开成切片时
// /12 网段占 29.4 MB，/8 约需 470 MB；而本结构恒为 8 字节。
type ipRange struct {
	first, last uint32
}

// Len 返回区间内地址数量。
func (r ipRange) Len() int { return int(r.last-r.first) + 1 }

// ForEach 按序逐个产出地址。fn 返回 false 即提前终止遍历。
func (r ipRange) ForEach(fn func(net.IP) bool) {
	for cur := uint64(r.first); cur <= uint64(r.last); cur++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, uint32(cur))
		if !fn(ip) {
			return
		}
	}
}

// Slice 展开为切片，仅供测试与小网段使用。
func (r ipRange) Slice() []net.IP {
	out := make([]net.IP, 0, r.Len())
	r.ForEach(func(ip net.IP) bool { out = append(out, ip); return true })
	return out
}

// expandCIDR 把网段解析为待探测地址区间。
// 规格：DESIGN.md §4.3 节点②。
//
// 边界（§9.3-B1/B2/B3）：
//   - /32 → 返回该地址本身（不可返回空）
//   - /31 → 返回两个地址，点对点网段无网络/广播地址概念，不得剔除
//   - 其余 → 剔除网络地址与广播地址
func expandCIDR(n *net.IPNet) (ipRange, error) {
	v4 := n.IP.To4()
	if v4 == nil {
		// §9.3-B7：IPv6 网段必须明确拒绝，不得静默返回空。
		return ipRange{}, fmt.Errorf("--cidr 暂不支持 IPv6 网段 %q，请传入 IPv4 网段", n.String())
	}
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return ipRange{}, fmt.Errorf("--cidr 掩码非法: %q", n.String())
	}

	base := binary.BigEndian.Uint32(v4.Mask(n.Mask))
	total := uint64(1) << uint(32-ones)

	var first, last uint32
	switch ones {
	case 32:
		first, last = base, base
	case 31:
		first, last = base, base+1
	default:
		first = base + 1
		last = base + uint32(total-2)
	}

	return ipRange{first: first, last: last}, nil
}

// parsePortRange 解析端口过滤范围。
// 规格：DESIGN.md §4.3 节点①，边界见 §9.3-B8~B12。
//
// 接受 "1-65535" 形式；单端口可写 "80" 或 "80-80"。
func parsePortRange(s string) (uint16, uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, fmt.Errorf("--ports 不能为空")
	}

	lo, hi := s, s
	if i := strings.IndexByte(s, '-'); i >= 0 {
		lo, hi = strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
	}

	parse := func(field, v string) (uint16, error) {
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("--ports 的%s %q 不是整数", field, v)
		}
		// §9.3-B10/B11：0 非合法端口，上界不得超过 65535。
		if n < 1 || n > 65535 {
			return 0, fmt.Errorf("--ports 的%s %d 超出范围，须在 1-65535 之间", field, n)
		}
		return uint16(n), nil
	}

	min, err := parse("下界", lo)
	if err != nil {
		return 0, 0, err
	}
	max, err := parse("上界", hi)
	if err != nil {
		return 0, 0, err
	}
	// §9.3-B9：下界不得大于上界。
	if min > max {
		return 0, 0, fmt.Errorf("--ports 下界 %d 大于上界 %d", min, max)
	}
	return min, max, nil
}
