package main

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// ---------- 名称转义还原（§7.3-①） ----------

// isSafeByte 判定一个字节还原后是否安全可见。
//
// 门槛定在 0x20 且排除 DEL：
//   - 低于 0x20 的是控制字符（换行、回车、ESC），还原它们等于亲手制造
//     §9.5-S2 要防的输出注入，故保持转义态。
//   - 高于 0x7f 的是 UTF-8 的前导/后续字节，必须还原，
//     否则 §9.3-B18 要求的中文、emoji 名称会变成一串 \228\184\173。
func isSafeByte(b byte) bool { return b >= 0x20 && b != 0x7f }

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// unescapeName 还原 DNS 展示格式的转义序列。
//
// 【与 §7.3-① 的偏差，不影响预期输出】
// 文档称空格被转义为 \032；实测 miekg/dns 产出的是反斜杠加空格。
// 本函数同时处理 \DDD 与 \X 两种通式，两种写法都能正确还原，故输出一致。
func unescapeName(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		// \DDD 三位十进制通式
		if i+3 < len(s) && isDigit(s[i+1]) && isDigit(s[i+2]) && isDigit(s[i+3]) {
			v := int(s[i+1]-'0')*100 + int(s[i+2]-'0')*10 + int(s[i+3]-'0')
			if v <= 255 && isSafeByte(byte(v)) {
				b.WriteByte(byte(v))
			} else {
				b.WriteString(s[i : i+4]) // 控制字符保持转义态
			}
			i += 4
			continue
		}
		// \X 通式（含 \  空格、\. 点、\\ 反斜杠）
		if isSafeByte(s[i+1]) {
			b.WriteByte(s[i+1])
		} else {
			b.WriteByte('\\')
			b.WriteByte(s[i+1])
		}
		i += 2
	}
	return b.String()
}

// ---------- 记录索引 ----------

// recordIndex 把一台设备的全部响应按记录类型归档，供后续按名查找。
// 所有切片均保持记录出现顺序，这是 §9.6-C6 的前提。
type recordIndex struct {
	ptr  map[string][]string // 所有者 → 目标列表，保序去重
	srv  map[string]*dns.SRV
	txt  map[string][]string
	a    map[string][]string
	aaaa map[string][]string
	ttl  map[string]uint32
}

func newRecordIndex() *recordIndex {
	return &recordIndex{
		ptr: map[string][]string{}, srv: map[string]*dns.SRV{},
		txt: map[string][]string{}, a: map[string][]string{},
		aaaa: map[string][]string{}, ttl: map[string]uint32{},
	}
}

func appendUnique(dst []string, v string) []string {
	for _, x := range dst {
		if x == v {
			return dst
		}
	}
	return append(dst, v)
}

// index 遍历响应的全部区段建立索引。
// §8.3：回答区、附加区、授权区一视同仁——设备通常把定位记录与描述记录
// 塞在附加区随 PTR 一起返回，只读回答区会丢掉大半深度信息。
func (ri *recordIndex) index(msgs []recvMsg) {
	for _, rm := range msgs {
		for _, section := range [][]dns.RR{rm.msg.Answer, rm.msg.Extra, rm.msg.Ns} {
			for _, rr := range section {
				// §9.4-E4：单条记录异常只跳过该条，不丢弃整个报文。
				if rr == nil || rr.Header() == nil {
					continue
				}
				name := strings.ToLower(rr.Header().Name)
				switch v := rr.(type) {
				case *dns.PTR:
					ri.ptr[name] = appendUnique(ri.ptr[name], v.Ptr)
				case *dns.SRV:
					if _, ok := ri.srv[name]; !ok {
						ri.srv[name] = v
					}
					ri.ttl[name] = rr.Header().Ttl
				case *dns.TXT:
					// §7.3-⑥ 零归一化：原样收下整个切片，不拆分、不排序、不去重。
					if _, ok := ri.txt[name]; !ok {
						ri.txt[name] = v.Txt
					}
					if _, ok := ri.ttl[name]; !ok {
						ri.ttl[name] = rr.Header().Ttl
					}
				case *dns.A:
					ri.a[name] = appendUnique(ri.a[name], v.A.String())
				case *dns.AAAA:
					ri.aaaa[name] = appendUnique(ri.aaaa[name], v.AAAA.String())
				}
			}
		}
	}
}

// ---------- probe.go 依赖的两个提取函数 ----------

// collectPTRTargets 取出某个所有者名下的全部 PTR 目标，保持出现顺序。
func collectPTRTargets(msgs []recvMsg, owner string) []string {
	ri := newRecordIndex()
	ri.index(msgs)
	return ri.ptr[strings.ToLower(dns.Fqdn(owner))]
}

// instancesMissingDetail 找出尚缺定位记录或描述记录的实例，供 Q3 补问（§8.3）。
func instancesMissingDetail(msgs []recvMsg) []string {
	ri := newRecordIndex()
	ri.index(msgs)

	var out []string
	for owner, targets := range ri.ptr {
		if owner == strings.ToLower(metaQuery) {
			continue // 元查询的目标是服务类型，不是实例
		}
		for _, inst := range targets {
			k := strings.ToLower(inst)
			if _, hasSRV := ri.srv[k]; hasSRV {
				if _, hasTXT := ri.txt[k]; hasTXT {
					continue
				}
			}
			out = appendUnique(out, inst)
		}
	}
	return out
}

// ---------- 节点④ 主体 ----------

// splitInstance 把实例全名拆成「实例名」与「服务类型全名」。
// 例：slw-nas\ [24:..]._workstation._tcp.local. → (还原后的实例名, _workstation._tcp.local.)
func splitInstance(fqdn string) (instance, svcType string, ok bool) {
	labels := dns.SplitDomainName(fqdn)
	if len(labels) < 4 {
		return "", "", false
	}
	return unescapeName(labels[0]), dns.Fqdn(strings.Join(labels[1:], ".")), true
}

// typeAndProto 从服务类型全名解出类型名与协议。
// 例：_qdiscover._tcp.local. → ("qdiscover", "tcp")
func typeAndProto(svcType string) (string, string, bool) {
	labels := dns.SplitDomainName(svcType)
	if len(labels) < 3 {
		return "", "", false
	}
	return strings.TrimPrefix(labels[0], "_"), strings.TrimPrefix(labels[1], "_"), true
}

// parseHost 把一台设备的全部响应解析成 Host。
// 规格：DESIGN.md §4.3 节点④。
func parseHost(src net.IP, msgs []recvMsg) *Host {
	ri := newRecordIndex()
	ri.index(msgs)

	h := &Host{IP: src}

	// 来源 1：服务类型清单。其顺序即输出中服务的排列顺序（§9.6-C6）。
	for _, t := range ri.ptr[strings.ToLower(metaQuery)] {
		h.PTRTypes = appendUnique(h.PTRTypes, t)
	}
	// 兜底：部分设备不响应元查询，但直接给出了服务类型的 PTR。
	if len(h.PTRTypes) == 0 {
		for owner := range ri.ptr {
			if strings.HasPrefix(owner, "_") && owner != strings.ToLower(metaQuery) {
				h.PTRTypes = appendUnique(h.PTRTypes, owner)
			}
		}
	}

	// 严格按 PTRTypes 顺序遍历，绝不排序（§9.6-C6）。
	for _, svcType := range h.PTRTypes {
		tName, proto, ok := typeAndProto(svcType)
		if !ok {
			continue
		}
		for _, instFQDN := range ri.ptr[strings.ToLower(svcType)] {
			key := strings.ToLower(instFQDN)
			inst, _, ok := splitInstance(instFQDN)
			if !ok {
				continue
			}
			s := Service{Name: inst, Type: tName, Proto: proto}

			if srv, ok := ri.srv[key]; ok {
				s.Port, s.HasPort = srv.Port, true // §4.4：仅在确有定位记录时才置位
				s.TTL = ri.ttl[key]
				if h.Hostname == "" {
					h.Hostname = strings.TrimSuffix(srv.Target, ".")
				}
				hk := strings.ToLower(srv.Target)
				if v := ri.a[hk]; len(v) > 0 && h.IPv4 == "" {
					h.IPv4 = v[0]
				}
				if v := ri.aaaa[hk]; len(v) > 0 && h.IPv6 == "" {
					h.IPv6 = v[0]
				}
			}
			// §7.3-⑥：整段透传，不做任何加工。
			s.TXT = ri.txt[key]
			if s.TTL == 0 {
				s.TTL = ri.ttl[key]
			}
			h.Services = append(h.Services, s)
		}
	}

	// 地址兜底：设备未在定位记录里给出主机名时，直接用响应源地址。
	if h.IPv4 == "" && src.To4() != nil {
		h.IPv4 = src.String()
	}
	if len(h.Services) == 0 && len(h.PTRTypes) == 0 {
		return nil
	}
	return h
}
