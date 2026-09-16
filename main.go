// mdnsscan 是一个网络资产测绘 CLI：给定网段与端口范围，
// 采集范围内设备主动声明的服务信息，含深度标识（型号、固件等自报键值对）。
//
// 完整设计与验收标准见同目录 DESIGN.md。
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"
)

// Config 是节点①的产物。规格：DESIGN.md §4.3 节点①。
type Config struct {
	Net         *net.IPNet
	PortMin     uint16
	PortMax     uint16
	Timeout     time.Duration
	Concurrency int
}

func main() { os.Exit(run()) }

// run 按 §4.1 的总流程编排六个节点，返回退出码。
// §4.1 总出参：正常 0（含无结果），参数非法 2。
func run() int {
	cidrFlag := flag.String("cidr", "", "待测绘网段，如 192.168.1.0/24（必填）")
	portsFlag := flag.String("ports", "1-65535", "端口过滤范围，如 1-10000")
	timeoutFlag := flag.Duration("timeout", 2*time.Second, "单个地址的总时间预算")
	concFlag := flag.Int("concurrency", 256, "并发探测数")
	flag.Parse()

	// ── 节点① 参数解析 ──────────────────────────────
	cfg, err := buildConfig(*cidrFlag, *portsFlag, *timeoutFlag, *concFlag)
	if err != nil {
		// §4.3 节点①失败列：指明哪个参数为何不合法，退出码 2，不得 panic。
		fmt.Fprintf(os.Stderr, "参数错误: %v\n", err)
		return 2
	}

	// §9.4-E7 / §9.6-C5：Ctrl-C 后取消要传播到每一条协程。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ── 节点② 目标生成 ──────────────────────────────
	targets, err := expandCIDR(cfg.Net)
	if err != nil {
		fmt.Fprintf(os.Stderr, "参数错误: %v\n", err)
		return 2
	}

	// ── 节点③a / ③b 双通道并行探测 ──────────────────
	groups := probeAll(ctx, cfg, targets, os.Stderr)

	// ── 节点⑤ 聚合过滤 ──────────────────────────────
	hosts := aggregate(groups, cfg)

	// ── 节点⑥ 渲染输出 ──────────────────────────────
	if len(hosts) == 0 {
		// §4.3 节点⑥边界：stdout 不输出任何内容，退出码仍为 0。
		fmt.Fprintln(os.Stderr, "未发现资产")
		return 0
	}
	fmt.Print(renderAll(hosts))
	return 0
}

func buildConfig(cidr, ports string, timeout time.Duration, conc int) (Config, error) {
	if cidr == "" {
		return Config{}, fmt.Errorf("--cidr 必填，如 --cidr 192.168.1.0/24")
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return Config{}, fmt.Errorf("--cidr %q 不是合法网段: %v", cidr, err)
	}
	min, max, err := parsePortRange(ports)
	if err != nil {
		return Config{}, err
	}
	// §9.3-B13/B14
	if timeout <= 0 {
		return Config{}, fmt.Errorf("--timeout 须大于 0，当前为 %v", timeout)
	}
	if conc <= 0 {
		return Config{}, fmt.Errorf("--concurrency 须大于 0，当前为 %d", conc)
	}
	return Config{Net: ipnet, PortMin: min, PortMax: max, Timeout: timeout, Concurrency: conc}, nil
}

// probeAll 并行跑两条探测通道，按响应源地址归组。
// 规格：§4.3 节点③a、③b；§8.4 两通道并行，耗时不串行叠加。
//
// warn 接收降级等非致命提示。作为参数而非直接写 os.Stderr，
// 是为了让测试能断言 §9.4-E9 的降级提示确实发出。
func probeAll(ctx context.Context, cfg Config, targets []net.IP, warn io.Writer) map[string][]recvMsg {
	var (
		mu     sync.Mutex
		groups = map[string][]recvMsg{}
		wg     sync.WaitGroup
	)
	add := func(ms []recvMsg) {
		mu.Lock()
		defer mu.Unlock()
		for _, m := range ms {
			k := m.src.String()
			groups[k] = append(groups[k], m)
		}
	}

	// 通道 ③a：组播兜底。失败即降级为纯单播，不中断整体（§9.4-E9）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		ms, err := probeMulticast(cfg.Timeout)
		if err != nil {
			// §9.4-E9：降级而非中断，单播通道照常完成。
			fmt.Fprintf(warn, "组播通道不可用，已降级为纯单播: %v\n", err)
			return
		}
		add(ms)
	}()

	// 通道 ③b：单播逐地址。worker pool 控制并发（§8.4）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		sem := make(chan struct{}, cfg.Concurrency)
		var inner sync.WaitGroup
		for _, ip := range targets {
			select {
			case <-ctx.Done():
				inner.Wait()
				return
			case sem <- struct{}{}:
			}
			inner.Add(1)
			go func(ip net.IP) {
				defer inner.Done()
				defer func() { <-sem }()
				if ms := probeUnicast(ip, cfg.Timeout); len(ms) > 0 {
					add(ms)
				}
			}(ip)
		}
		inner.Wait()
	}()

	wg.Wait()
	return groups
}

// aggregate 是节点⑤。规格：DESIGN.md §4.3 节点⑤。
func aggregate(groups map[string][]recvMsg, cfg Config) []*Host {
	var hosts []*Host
	for key, msgs := range groups {
		src := net.ParseIP(key)
		// 步骤 1：先用网段过滤组播通道带回的范围外响应源（§9.3-B22）。
		if src == nil || !cfg.Net.Contains(src) {
			continue
		}
		h := parseHost(src, msgs)
		if h == nil {
			continue
		}
		// 步骤 4：按端口范围过滤。
		h.Services = filterByPort(h.Services, cfg.PortMin, cfg.PortMax)
		if len(h.Services) == 0 {
			continue
		}
		hosts = append(hosts, h)
	}
	// §9.6-C6：主机之间按 IP 排序以保证可复现；
	// 主机内部的服务顺序由 parseHost 按服务类型清单顺序生成，此处不得再排。
	sort.Slice(hosts, func(i, j int) bool {
		return compareIP(hosts[i].IP, hosts[j].IP) < 0
	})
	return hosts
}

// filterByPort 按端口范围过滤。
// §4.3 节点⑤关键决策：无端口的服务不参与端口过滤，一律保留——
// 它不归属任何端口区间，滤掉会丢失 device-info 这类承载型号信息的条目。
func filterByPort(in []Service, min, max uint16) []Service {
	out := in[:0:0]
	for _, s := range in {
		if !s.HasPort || (s.Port >= min && s.Port <= max) {
			out = append(out, s)
		}
	}
	return out
}

func compareIP(a, b net.IP) int {
	a4, b4 := a.To16(), b.To16()
	for i := range a4 {
		switch {
		case a4[i] < b4[i]:
			return -1
		case a4[i] > b4[i]:
			return 1
		}
	}
	return 0
}
