package main

import "net"

// Host 是一台被发现设备的聚合结果。
// 规格：DESIGN.md §6 数据模型。
type Host struct {
	IP       net.IP
	IPv4     string
	IPv6     string
	Hostname string

	// PTRTypes 是设备声明的全部服务类型，用于渲染 answers: PTR: 段。
	// 必须保持设备返回的原始顺序：§9.6-C6 规定同一主机内的服务顺序
	// 与本切片一致，任何排序都会打乱输出。
	PTRTypes []string

	Services []Service
}

// Service 是一条服务记录。
// 规格：DESIGN.md §6、§7.2。
type Service struct {
	Name  string // 实例名，已做转义还原（§7.3-①）
	Type  string // 服务类型，如 http / smb / qdiscover
	Proto string // tcp / udp
	Port  uint16
	TTL   uint32

	// HasPort 显式标记是否存在端口。
	// §4.4 规定无端口服务（如 device-info）不得输出 0/tcp，
	// 故不能用 Port == 0 来判断——那会与"端口真为 0"混淆。
	HasPort bool

	// TXT 是设备自报的键值对，即"深度标识"的主体。
	//
	// 【与 §6 的偏差】原设计为 []KV（拆成键值两段）。实现时改为原始字符串切片：
	// 输出格式只是把各项用逗号连起来，从不按键查找，拆分纯属多余；
	// 且不拆分则 §7.3-③（只按第一个等号切分）与 §7.3-④（无等号项原样保留）
	// 自动成立，无法写错。输出结果完全一致。
	TXT []string
}

// hostKey 用于按 IP 聚合（§4.3 节点⑤）。
func (h *Host) hostKey() string { return h.IP.String() }
