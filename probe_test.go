package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestMulticastDegradation 覆盖 §9.4-E9：
// 组播套接字不可用时必须降级为纯单播，发出提示但不中断整体。
//
// 该场景在真实环境中难以构造（组播套接字几乎总能创建成功），
// 故通过注入 listenUDP 失败来模拟。
func TestMulticastDegradation(t *testing.T) {
	orig := listenUDP
	t.Cleanup(func() { listenUDP = orig })
	listenUDP = func(string, *net.UDPAddr) (*net.UDPConn, error) {
		return nil, errors.New("模拟故障：组播套接字创建失败")
	}

	// 其一：probeMulticast 必须如实上报错误，不得吞掉。
	if _, err := probeMulticast(context.Background(), 100*time.Millisecond); err == nil {
		t.Fatal("组播套接字创建失败时，probeMulticast 应返回错误")
	}

	// 其二：probeAll 必须发出降级提示，且单播通道照常收尾。
	// 目标用 TEST-NET-2（RFC 5737 保留段），保证无人响应。
	_, ipnet, err := net.ParseCIDR("198.51.100.0/30")
	if err != nil {
		t.Fatal(err)
	}
	targets, err := expandCIDR(ipnet)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Net: ipnet, PortMin: 1, PortMax: 65535,
		Timeout: 200 * time.Millisecond, Concurrency: 4}

	var warn bytes.Buffer
	done := make(chan map[string][]recvMsg, 1)
	go func() { done <- probeAll(context.Background(), cfg, targets, &warn) }()

	select {
	case groups := <-done:
		if len(groups) != 0 {
			t.Errorf("保留网段不应有响应，实际收到 %d 组", len(groups))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("组播失败后 probeAll 未能收尾，降级路径存在阻塞")
	}

	if !strings.Contains(warn.String(), "已降级为纯单播") {
		t.Errorf("§9.4-E9：未发出降级提示，实际输出为 %q", warn.String())
	}
}

// TestMulticastSuccessIsSilent 反向确认：组播正常时不得输出降级提示，
// 以免误导使用者以为功能未生效。
func TestMulticastSuccessIsSilent(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("198.51.100.0/31")
	if err != nil {
		t.Fatal(err)
	}
	targets, err := expandCIDR(ipnet)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Net: ipnet, PortMin: 1, PortMax: 65535,
		Timeout: 200 * time.Millisecond, Concurrency: 2}

	var warn bytes.Buffer
	probeAll(context.Background(), cfg, targets, &warn)

	if strings.Contains(warn.String(), "已降级") {
		t.Errorf("组播可用时不应输出降级提示，实际输出为 %q", warn.String())
	}
}

// TestCancellationPropagates 覆盖 §9.6-C5：
// 取消后必须迅速收尾，不得等满整个超时预算。
//
// 预算故意设为 30s：若取消未能传播到阻塞中的 UDP 读操作，
// 本用例会实打实地耗时 30 秒。
func TestCancellationPropagates(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("198.51.100.0/30")
	if err != nil {
		t.Fatal(err)
	}
	targets, err := expandCIDR(ipnet)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Net: ipnet, PortMin: 1, PortMax: 65535,
		Timeout: 30 * time.Second, Concurrency: 4}

	ctx, cancel := context.WithCancel(context.Background())
	var warn bytes.Buffer
	done := make(chan struct{})
	go func() {
		probeAll(ctx, cfg, targets, &warn)
		close(done)
	}()

	time.Sleep(150 * time.Millisecond) // 让探测真正进入阻塞读
	start := time.Now()
	cancel()

	select {
	case <-done:
		if el := time.Since(start); el > 3*time.Second {
			t.Errorf("§9.6-C5：取消后耗时 %v 才收尾，预算为 30s，说明取消未有效传播", el)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("§9.6-C5：取消后 probeAll 未能在 6 秒内收尾")
	}
}

// TestNoGoroutineLeak 覆盖 §9.6-C3：探测结束后协程数应回落至基线。
func TestNoGoroutineLeak(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("198.51.100.0/29")
	if err != nil {
		t.Fatal(err)
	}
	targets, err := expandCIDR(ipnet)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Net: ipnet, PortMin: 1, PortMax: 65535,
		Timeout: 200 * time.Millisecond, Concurrency: 8}

	baseline := runtime.NumGoroutine()
	var warn bytes.Buffer
	probeAll(context.Background(), cfg, targets, &warn)

	// 轮询等待回落：runtime 回收协程有延迟，直接比对会偶发失败。
	for i := 0; i < 60; i++ {
		if runtime.NumGoroutine() <= baseline+1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("§9.6-C3：协程数未回落，基线 %d，当前 %d", baseline, runtime.NumGoroutine())
}

// TestConcurrencyCap 覆盖 §9.5-S5 的并发截断逻辑。
func TestConcurrencyCap(t *testing.T) {
	cases := []struct {
		name          string
		requested     int
		targets       int
		want          int
		wantTruncated bool
	}{
		{"超过硬上限须截断", 100000, 5000, maxConcurrency, true},
		{"上限内原样保留", 256, 5000, 256, false},
		{"目标数少于并发数时收敛", 256, 10, 10, false},
		{"最小值为 1", 1, 100, 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var warn bytes.Buffer
			got := effectiveConcurrency(c.requested, c.targets, &warn)
			if got != c.want {
				t.Errorf("effectiveConcurrency(%d, %d) = %d，期望 %d",
					c.requested, c.targets, got, c.want)
			}
			truncated := strings.Contains(warn.String(), "已截断")
			if truncated != c.wantTruncated {
				t.Errorf("截断提示 = %v，期望 %v（实际输出 %q）",
					truncated, c.wantTruncated, warn.String())
			}
		})
	}
}

// TestConcurrencyBound 覆盖 §9.6-C2：实际并发协程数不得超过设定值。
//
// 用阻塞桩替换套接字创建：所有通过信号量的协程都会卡在桩里，
// 此时读取计数即为真实并发数。这样测量精确且不依赖计时。
func TestConcurrencyBound(t *testing.T) {
	origDial, origListen := dialUDP, listenUDP
	t.Cleanup(func() { dialUDP, listenUDP = origDial, origListen })

	// 关掉组播通道，避免其套接字干扰计数。
	listenUDP = func(string, *net.UDPAddr) (*net.UDPConn, error) {
		return nil, errors.New("测试中禁用组播")
	}

	gate := make(chan struct{})
	var inFlight int64
	dialUDP = func(string, *net.UDPAddr, *net.UDPAddr) (*net.UDPConn, error) {
		atomic.AddInt64(&inFlight, 1)
		<-gate // 卡住，使并发数可被静态观测
		return nil, errors.New("测试桩")
	}

	const want = 16
	_, ipnet, err := net.ParseCIDR("198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}
	targets, err := expandCIDR(ipnet)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Net: ipnet, PortMin: 1, PortMax: 65535,
		Timeout: time.Second, Concurrency: want}

	var warn bytes.Buffer
	done := make(chan struct{})
	go func() { probeAll(context.Background(), cfg, targets, &warn); close(done) }()

	time.Sleep(300 * time.Millisecond) // 等并发数稳定在上限
	got := atomic.LoadInt64(&inFlight)
	close(gate)
	<-done

	if got > want {
		t.Errorf("§9.6-C2：实际并发 %d 超过设定值 %d", got, want)
	}
	if got < want {
		t.Errorf("实际并发 %d 未达设定值 %d，worker pool 没打满", got, want)
	}
}
