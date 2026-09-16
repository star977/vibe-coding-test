package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
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
	if _, err := probeMulticast(100 * time.Millisecond); err == nil {
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
