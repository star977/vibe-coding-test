package main

import (
	"strconv"
	"strings"
)

// renderHost 渲染单台设备。
// 规格：DESIGN.md §4.4「格式规则」，逐条对齐示例。
func renderHost(h *Host, b *strings.Builder) {
	b.WriteString("services:\n")

	for _, s := range h.Services {
		// 服务行。§4.4：无端口服务退化为 "<服务名>:"，不得输出 0/tcp。
		if s.HasPort {
			b.WriteString(strconv.Itoa(int(s.Port)))
			b.WriteByte('/')
			b.WriteString(s.Proto)
			b.WriteByte(' ')
		}
		b.WriteString(s.Type)
		b.WriteString(":\n")

		// 属性行，顺序固定：Name → IPv4 → IPv6 → Hostname → TTL → 自报键值对。
		b.WriteString("Name=" + s.Name + "\n")
		if h.IPv4 != "" { // §9.3-B17：无值则整行省略，不输出空值
			b.WriteString("IPv4=" + h.IPv4 + "\n")
		}
		if h.IPv6 != "" {
			b.WriteString("IPv6=" + h.IPv6 + "\n")
		}
		if h.Hostname != "" {
			b.WriteString("Hostname=" + h.Hostname + "\n")
		}
		b.WriteString("TTL=" + strconv.FormatUint(uint64(s.TTL), 10) + "\n")

		// 深度标识。§7.3-⑤：空描述记录不产生空行。
		// §7.3-②⑥：原序、原样，用逗号连接，不排序不去重不改写。
		if line := strings.Join(s.TXT, ","); line != "" {
			b.WriteString(line + "\n")
		}
	}

	// 尾部段。示例中服务类型不带结尾的点。
	b.WriteString("answers:\nPTR:\n")
	for _, t := range h.PTRTypes {
		b.WriteString(strings.TrimSuffix(t, ".") + "\n")
	}
}

// renderAll 渲染全部设备。
//
// 【设计文档未覆盖处 — 待定】§4.4 的示例只含一台设备，
// 未规定多台设备时的整体结构。此处暂按「每台设备一个完整区块」实现。
// 若改为全局扁平结构，只需改动本函数。
func renderAll(hosts []*Host) string {
	var b strings.Builder
	for _, h := range hosts {
		renderHost(h, &b)
	}
	return b.String()
}
