package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// 多设备测试。
//
// 分两个层次，原因是源地址的可控性受操作系统限制：
//
//   并发多目标（始终运行）——多个响应端各占一个端口，按目标地址分流。
//     验证并发处理多个应答目标的路径，但源地址同为 127.0.0.1。
//
//   独立源地址（按环境跳过）——各响应端绑定不同的环回别名，
//     共用同一端口，因此无需任何注入，走的是完全真实的路径。
//     macOS 默认只分配 127.0.0.1，需手工添加别名；Linux 默认整个
//     127/8 可用，本用例会直接运行。
// ═══════════════════════════════════════════════════════════════

// deviceProfile 描述一台待模拟的设备。
type deviceProfile struct {
	hostname string
	svcType  string
	instance string
	port     uint16
	txt      []string
}

func threeProfiles() []deviceProfile {
	return []deviceProfile{
		{"nas.local.", "qdiscover", "nas", 5000,
			[]string{"model=TS-464C", "fwVer=5.2.9"}},
		{"printer.local.", "ipp", "printer", 631,
			[]string{"ty=HP LaserJet", "adminurl=http://printer/admin"}},
		{"box.local.", "airplay", "box", 7000,
			[]string{"model=AppleTV6,2", "srcvers=960.13.1"}},
	}
}

func (p deviceProfile) responder(bindIP string, bindPort int) *fakeResponder {
	return &fakeResponder{
		bindIP:   bindIP,
		bindPort: bindPort,
		hostname: p.hostname,
		v4:       "127.0.0.1",
		svcs: []fakeSvc{
			{typ: p.svcType, instance: p.instance, port: p.port, txt: p.txt},
		},
	}
}

// TestMultiDeviceConcurrentTargets 验证并发处理多个应答目标。
//
// 三个响应端各占一个端口，按目标地址末位字节分流。
// 源地址同为 127.0.0.1，故三者会聚合成一台设备——
// 但这不影响本用例的目的：确认三个目标的数据都经真实套接字取回，
// 没有因并发而丢失。
func TestMultiDeviceConcurrentTargets(t *testing.T) {
	disableMulticast(t)

	profiles := threeProfiles()
	routes := map[byte]int{}
	for i, p := range profiles {
		r := startFakeResponder(t, p.responder("", 0))
		routes[byte(i+1)] = r.port // .1 .2 .3
	}
	blackhole := startRawResponder(t, nil, 0)
	routeByLastOctet(t, routes, blackhole)

	_, ipnet, err := net.ParseCIDR("127.0.0.0/29")
	if err != nil {
		t.Fatal(err)
	}
	targets, err := expandCIDR(ipnet)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Net: ipnet, PortMin: 1, PortMax: 65535,
		Timeout: 1500 * time.Millisecond, Concurrency: 8}

	var warn bytes.Buffer
	groups := probeAll(context.Background(), cfg, targets, &warn)
	if len(groups) == 0 {
		t.Fatal("三个响应端均未产出响应")
	}
	out := renderAll(aggregate(groups, cfg))

	// 三个目标的服务与深度标识都必须到位，一个不能少。
	for _, p := range profiles {
		if !strings.Contains(out, fmt.Sprintf("%d/tcp %s:", p.port, p.svcType)) {
			t.Errorf("目标 %s 的服务行缺失\n完整输出:\n%s", p.svcType, out)
		}
		for _, kv := range p.txt {
			if !strings.Contains(out, kv) {
				t.Errorf("目标 %s 的深度标识 %q 缺失", p.svcType, kv)
			}
		}
	}
}

// loopbackAliasesAvailable 检查一组环回别名是否可绑定。
func loopbackAliasesAvailable(ips []string) bool {
	for _, ip := range ips {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip), Port: 0})
		if err != nil {
			return false
		}
		_ = c.Close()
	}
	return true
}

// TestMultiDeviceDistinctSourceIPs 用独立源地址验证真实的多设备场景。
//
// 各响应端绑定不同的环回别名并共用同一端口，因此**不需要任何注入**：
// 探测按真实流程逐地址 dial，收到的响应带有各自不同的源地址，
// 聚合与渲染走的是与生产完全一致的路径。
//
// 这是对「多台设备同时响应」最接近真实的自动化验证。
func TestMultiDeviceDistinctSourceIPs(t *testing.T) {
	aliases := []string{"127.0.0.2", "127.0.0.3", "127.0.0.4"}
	if !loopbackAliasesAvailable(aliases) {
		t.Skipf("本用例需要环回别名 %v。\n"+
			"macOS 默认只分配 127.0.0.1，可执行以下命令启用（需管理员权限）：\n"+
			"    sudo ifconfig lo0 alias 127.0.0.2 up\n"+
			"    sudo ifconfig lo0 alias 127.0.0.3 up\n"+
			"    sudo ifconfig lo0 alias 127.0.0.4 up\n"+
			"Linux 默认整个 127/8 可用，本用例会直接运行。", aliases)
	}
	disableMulticast(t)

	// 先在第一个别名上取一个空闲端口，其余别名复用同一端口号。
	// 地址不同即可共存，因此无需分流注入。
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(aliases[0]), Port: 0})
	if err != nil {
		t.Fatalf("探测空闲端口失败: %v", err)
	}
	shared := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	profiles := threeProfiles()
	for i, p := range profiles {
		r := p.responder(aliases[i], shared)
		r.v4 = aliases[i]
		startFakeResponder(t, r)
	}

	orig := mdnsPort
	mdnsPort = shared
	t.Cleanup(func() { mdnsPort = orig })

	_, ipnet, err := net.ParseCIDR("127.0.0.0/29")
	if err != nil {
		t.Fatal(err)
	}
	targets, err := expandCIDR(ipnet)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Net: ipnet, PortMin: 1, PortMax: 65535,
		Timeout: 1500 * time.Millisecond, Concurrency: 8}

	var warn bytes.Buffer
	groups := probeAll(context.Background(), cfg, targets, &warn)
	hosts := aggregate(groups, cfg)

	if len(hosts) != len(aliases) {
		t.Fatalf("期望聚合出 %d 台独立设备，实际 %d 台（源地址未被正确区分）",
			len(aliases), len(hosts))
	}
	// §9.6-C6：主机之间须按 IP 升序。
	for i, want := range aliases {
		if got := hosts[i].IP.String(); got != want {
			t.Errorf("第 %d 台设备为 %s，期望 %s", i, got, want)
		}
	}
	out := renderAll(hosts)
	if n := strings.Count(out, "services:\n"); n != len(aliases) {
		t.Errorf("期望 %d 个独立区块，实际 %d 个", len(aliases), n)
	}
	// 每台设备的主机名与深度标识都应落到自己的区块里。
	for _, p := range profiles {
		if !strings.Contains(out, "Hostname="+strings.TrimSuffix(p.hostname, ".")) {
			t.Errorf("设备 %s 的主机名缺失", p.hostname)
		}
		for _, kv := range p.txt {
			if !strings.Contains(out, kv) {
				t.Errorf("设备 %s 的深度标识 %q 缺失", p.hostname, kv)
			}
		}
	}
}
