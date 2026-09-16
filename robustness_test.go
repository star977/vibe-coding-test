package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// unreachableDial 返回一个模拟「网络不可达」的 dial 实现。
func unreachableDial() func(string, *net.UDPAddr, *net.UDPAddr) (*net.UDPConn, error) {
	return func(network string, _, raddr *net.UDPAddr) (*net.UDPConn, error) {
		return nil, &net.OpError{Op: "dial", Net: network, Addr: raddr,
			Err: errors.New("network is unreachable")}
	}
}

func smallScan(t *testing.T, cidr string, timeout time.Duration) (Config, ipRange) {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := expandCIDR(ipnet)
	if err != nil {
		t.Fatal(err)
	}
	return Config{Net: ipnet, PortMin: 1, PortMax: 65535,
		Timeout: timeout, Concurrency: 8}, targets
}

// TestE5NetworkUnusableIsReported 覆盖 §9.4-E5：
// 接口不可用时必须明确报错，**不得静默跑完再输出空**。
//
// 这条原本是实现缺口：dial 失败与「目标无响应」都走同一条静默
// 跳过的路径，接口断开时程序会照常输出「未发现资产」，
// 把环境故障伪装成扫描结果。
func TestE5NetworkUnusableIsReported(t *testing.T) {
	origDial, origListen := dialUDP, listenUDP
	t.Cleanup(func() { dialUDP, listenUDP = origDial, origListen })
	dialUDP = unreachableDial()
	listenUDP = func(string, *net.UDPAddr) (*net.UDPConn, error) {
		return nil, errors.New("network is unreachable")
	}

	cfg, targets := smallScan(t, "192.168.1.0/29", 200*time.Millisecond)
	var warn bytes.Buffer
	groups := probeAll(context.Background(), cfg, targets, &warn)

	if len(groups) != 0 {
		t.Errorf("网络不可达却收到 %d 组响应", len(groups))
	}
	out := warn.String()
	if !strings.Contains(out, "全部无法建立连接") {
		t.Errorf("§9.4-E5：未给出明确警告，实际输出 %q", out)
	}
	// 警告必须点明这与「未发现资产」不是一回事，否则等于没说。
	if !strings.Contains(out, "未发现资产") {
		t.Errorf("警告未区分环境故障与空结果，实际输出 %q", out)
	}
}

// TestE5NoFalseAlarmWhenSomeSucceed 反向确认：
// 只要有地址能连上，就不该报「全部无法建立连接」。
// 少了这条，上一个用例可以用「永远报警」来通过。
func TestE5NoFalseAlarmWhenSomeSucceed(t *testing.T) {
	r := startFakeResponder(t, nasResponder())
	pointProbesAtFake(t, r)

	origListen := listenUDP
	t.Cleanup(func() { listenUDP = origListen })
	listenUDP = func(string, *net.UDPAddr) (*net.UDPConn, error) {
		return nil, errors.New("组播禁用，与本用例无关")
	}

	cfg, targets := smallScan(t, "127.0.0.0/30", 600*time.Millisecond)
	var warn bytes.Buffer
	groups := probeAll(context.Background(), cfg, targets, &warn)

	if len(groups) == 0 {
		t.Fatal("假响应端应至少产出一组响应")
	}
	if strings.Contains(warn.String(), "全部无法建立连接") {
		t.Errorf("有地址连通却误报接口故障，实际输出 %q", warn.String())
	}
}

// TestE6PermissionDeniedSurfacesCause 覆盖 §9.4-E6：
// 无权限时须明确提示**具体原因**，而非只说「不可用」。
func TestE6PermissionDeniedSurfacesCause(t *testing.T) {
	origListen := listenUDP
	t.Cleanup(func() { listenUDP = origListen })
	listenUDP = func(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
		return nil, &net.OpError{Op: "listen", Net: network, Addr: laddr,
			Err: os.ErrPermission}
	}

	r := startFakeResponder(t, nasResponder())
	pointProbesAtFake(t, r)

	cfg, targets := smallScan(t, "127.0.0.0/30", 600*time.Millisecond)
	var warn bytes.Buffer
	probeAll(context.Background(), cfg, targets, &warn)

	out := warn.String()
	if !strings.Contains(out, "已降级为纯单播") {
		t.Errorf("§9.4-E6：未提示降级，实际输出 %q", out)
	}
	// 原因必须原样带出，否则使用者无从判断是权限、端口占用还是别的问题。
	if !strings.Contains(out, os.ErrPermission.Error()) {
		t.Errorf("§9.4-E6：未带出具体原因 %q，实际输出 %q",
			os.ErrPermission.Error(), out)
	}
}
