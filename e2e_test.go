package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════
// 端到端测试，两种粒度：
//
//   进程内（runCLI）—— 直接调用 run()，可配合假响应端验证完整输出，
//                      并覆盖 main.go 中原本零覆盖的 run / usage。
//   真实子进程      —— 构建二进制后作为独立进程执行，验证退出码、
//                      stdout/stderr 分流、未知参数处理等进程级行为。
// ═══════════════════════════════════════════════════════════════

var e2eBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "mdnsscan-e2e")
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e 临时目录创建失败: %v\n", err)
		os.Exit(1)
	}
	e2eBinary = filepath.Join(dir, "mdnsscan")
	if out, err := exec.Command("go", "build", "-o", e2eBinary, ".").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e 前置构建失败: %v\n%s\n", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// runCLI 在进程内跑一次完整 CLI 流程，捕获 stdout、stderr 与退出码。
//
// 每次调用前重置 flag.CommandLine：flag 包的全局注册表不允许重复
// 注册同名参数，不重置则第二次调用会 panic。
func runCLI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()

	origArgs, origOut, origErr := os.Args, os.Stdout, os.Stderr
	origCmdLine := flag.CommandLine
	defer func() {
		os.Args, os.Stdout, os.Stderr = origArgs, origOut, origErr
		flag.CommandLine = origCmdLine
	}()

	// 与生产一致使用 ExitOnError，故进程内只传能正常解析的参数；
	// 未知参数一类交由子进程用例验证。
	flag.CommandLine = flag.NewFlagSet("mdnsscan", flag.ExitOnError)
	os.Args = append([]string{"mdnsscan"}, args...)

	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = wOut, wErr

	var outBuf, errBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(&outBuf, rOut) }()
	go func() { defer wg.Done(); _, _ = io.Copy(&errBuf, rErr) }()

	code = run()

	_ = wOut.Close()
	_ = wErr.Close()
	wg.Wait()
	return outBuf.String(), errBuf.String(), code
}

// ───────────────── 进程内 e2e ─────────────────

// TestE2EFullFlow 走完整 CLI：参数 → 探测 → 输出，并核对格式。
func TestE2EFullFlow(t *testing.T) {
	r := startFakeResponder(t, nasResponder())
	pointProbesAtFake(t, r)
	// 把组播也指向本地假响应端，避免真实组播引入环境噪声。
	origGroup := mdnsGroupV4
	mdnsGroupV4 = net.ParseIP("127.0.0.1")
	t.Cleanup(func() { mdnsGroupV4 = origGroup })

	stdout, stderr, code := runCLI(t,
		"--cidr", "127.0.0.1/32", "--ports", "1-65535", "--timeout", "2s")

	if code != 0 {
		t.Fatalf("退出码 %d，期望 0（stderr: %s）", code, stderr)
	}
	// 输出结构须与 §4.4 示例一致。
	wants := []string{
		"services:\n",
		"9/tcp workstation:\n",
		"Name=slw-nas [24:5e:be:69:a3:13]\n",
		"\ndevice-info:\n",
		"Hostname=slw-nas.local\n",
		"accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214\n",
		"answers:\nPTR:\n",
	}
	for _, w := range wants {
		if !strings.Contains(stdout, w) {
			t.Errorf("stdout 缺少 %q\n完整 stdout:\n%s", w, stdout)
		}
	}
	// stdout 只放结果，不得混入提示信息。
	if strings.Contains(stdout, "未发现") || strings.Contains(stdout, "降级") {
		t.Errorf("提示信息污染了 stdout:\n%s", stdout)
	}
	if strings.Contains(stdout, "\n\n") {
		t.Errorf("§7.3-⑤：输出中出现空行:\n%s", stdout)
	}
}

// TestE2EPortFilterEndToEnd 从命令行验证端口过滤，
// 并确认无端口服务仍被保留（§4.3 节点⑤）。
func TestE2EPortFilterEndToEnd(t *testing.T) {
	r := startFakeResponder(t, nasResponder())
	pointProbesAtFake(t, r)
	origGroup := mdnsGroupV4
	mdnsGroupV4 = net.ParseIP("127.0.0.1")
	t.Cleanup(func() { mdnsGroupV4 = origGroup })

	stdout, _, code := runCLI(t,
		"--cidr", "127.0.0.1/32", "--ports", "5000-5000", "--timeout", "2s")
	if code != 0 {
		t.Fatalf("退出码 %d，期望 0", code)
	}
	if strings.Contains(stdout, "9/tcp workstation") {
		t.Error("范围外的 9/tcp 未被滤除")
	}
	if !strings.Contains(stdout, "5000/tcp qdiscover") {
		t.Error("范围内的 5000/tcp 被误滤")
	}
	if !strings.Contains(stdout, "\ndevice-info:\n") {
		t.Error("无端口服务被误滤，型号信息会因此丢失")
	}
}

// TestE2EEmptyResult 覆盖 §9.4-E1：
// 无结果时 stdout 为空、提示走 stderr、退出码仍为 0。
func TestE2EEmptyResult(t *testing.T) {
	orig := mdnsPort
	mdnsPort = 1 // 本地必然无监听
	t.Cleanup(func() { mdnsPort = orig })

	stdout, stderr, code := runCLI(t,
		"--cidr", "198.51.100.0/30", "--timeout", "500ms")

	if code != 0 {
		t.Errorf("退出码 %d，空结果不是错误，应为 0", code)
	}
	if stdout != "" {
		t.Errorf("stdout 应为空，实际 %q", stdout)
	}
	if !strings.Contains(stderr, "未发现资产") {
		t.Errorf("stderr 应给出提示，实际 %q", stderr)
	}
}

// TestE2EParamErrors 覆盖 §4.3 节点① 与 §9.3-B5~B14：
// 参数非法时退出码 2、报错指明参数、stdout 保持干净。
func TestE2EParamErrors(t *testing.T) {
	cases := []struct {
		spec       string
		args       []string
		wantSubstr string
	}{
		{"缺 cidr", []string{}, "--cidr 必填"},
		{"cidr 非法", []string{"--cidr", "abc"}, "不是合法网段"},
		{"掩码越界", []string{"--cidr", "192.168.1.0/33"}, "不是合法网段"},
		{"IPv6 网段", []string{"--cidr", "fe80::/64"}, "不支持 IPv6"},
		{"端口下界大于上界", []string{"--cidr", "192.168.1.0/30", "--ports", "100-50"}, "大于上界"},
		{"端口为 0", []string{"--cidr", "192.168.1.0/30", "--ports", "0-100"}, "超出范围"},
		{"端口越界", []string{"--cidr", "192.168.1.0/30", "--ports", "1-70000"}, "超出范围"},
		{"端口非整数", []string{"--cidr", "192.168.1.0/30", "--ports", "abc"}, "不是整数"},
		{"超时为零", []string{"--cidr", "192.168.1.0/30", "--timeout", "0"}, "--timeout"},
		{"并发为零", []string{"--cidr", "192.168.1.0/30", "--concurrency", "0"}, "--concurrency"},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			stdout, stderr, code := runCLI(t, c.args...)
			if code != 2 {
				t.Errorf("退出码 %d，期望 2", code)
			}
			if stdout != "" {
				t.Errorf("参数出错时 stdout 应为空，实际 %q", stdout)
			}
			if !strings.Contains(stderr, c.wantSubstr) {
				t.Errorf("stderr %q 未包含 %q", stderr, c.wantSubstr)
			}
		})
	}
}

// TestE2EUsage 覆盖 usage()：帮助须含用法、示例与关键语义说明。
func TestE2EUsage(t *testing.T) {
	origCmdLine := flag.CommandLine
	defer func() { flag.CommandLine = origCmdLine }()

	var buf bytes.Buffer
	flag.CommandLine = flag.NewFlagSet("mdnsscan", flag.ContinueOnError)
	flag.CommandLine.SetOutput(&buf)
	flag.String("cidr", "", "待测绘网段")
	usage()

	out := buf.String()
	for _, want := range []string{"用法:", "示例:", "选项:", "过滤范围", "退出码", "授权"} {
		if !strings.Contains(out, want) {
			t.Errorf("帮助信息缺少 %q\n%s", want, out)
		}
	}
}

// ───────────────── 真实子进程 e2e ─────────────────

func execBinary(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(e2eBinary, args...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("执行二进制失败: %v", err)
	}
	return o.String(), e.String(), code
}

// TestE2EBinaryHelp 验证真实进程的 --help 行为。
func TestE2EBinaryHelp(t *testing.T) {
	stdout, stderr, code := execBinary(t, "--help")
	out := stdout + stderr
	if code != 0 {
		t.Errorf("--help 退出码 %d，期望 0", code)
	}
	for _, want := range []string{"mdnsscan", "用法:", "示例:", "--cidr", "过滤范围"} {
		if !strings.Contains(out, want) {
			t.Errorf("--help 输出缺少 %q", want)
		}
	}
}

// TestE2EBinaryUnknownFlag 验证未知参数的进程级行为。
// 这一路径由 flag 包的 ExitOnError 处理，进程内无法测试。
func TestE2EBinaryUnknownFlag(t *testing.T) {
	stdout, stderr, code := execBinary(t, "--bogus")
	if code != 2 {
		t.Errorf("未知参数退出码 %d，期望 2", code)
	}
	if !strings.Contains(stderr, "bogus") {
		t.Errorf("stderr 应指出未知参数，实际 %q", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout 应为空，实际 %q", stdout)
	}
}

// TestE2EBinaryExitCodes 在真实进程里核对退出码约定。
func TestE2EBinaryExitCodes(t *testing.T) {
	cases := []struct {
		spec string
		args []string
		want int
	}{
		{"参数非法", []string{"--cidr", "abc"}, 2},
		{"缺必填参数", []string{}, 2},
		{"无结果仍为成功", []string{"--cidr", "198.51.100.0/30", "--timeout", "300ms"}, 0},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			_, _, code := execBinary(t, c.args...)
			if code != c.want {
				t.Errorf("退出码 %d，期望 %d", code, c.want)
			}
		})
	}
}

// TestE2EBinaryStreamSeparation 验证 stdout 与 stderr 分流：
// stdout 只放结果，提示与错误一律走 stderr，保证输出可被管道处理。
func TestE2EBinaryStreamSeparation(t *testing.T) {
	stdout, stderr, _ := execBinary(t,
		"--cidr", "198.51.100.0/30", "--timeout", "300ms", "--concurrency", "100000")

	if stdout != "" {
		t.Errorf("无结果时 stdout 应为空，实际 %q", stdout)
	}
	if !strings.Contains(stderr, "已截断") {
		t.Errorf("并发截断提示应出现在 stderr，实际 %q", stderr)
	}
	if !strings.Contains(stderr, "未发现资产") {
		t.Errorf("空结果提示应出现在 stderr，实际 %q", stderr)
	}
}

// TestE2EBinaryCompletesWithinBudget 验证真实进程不会挂死。
func TestE2EBinaryCompletesWithinBudget(t *testing.T) {
	start := time.Now()
	_, _, code := execBinary(t, "--cidr", "198.51.100.0/24", "--timeout", "1s")
	elapsed := time.Since(start)
	if code != 0 {
		t.Errorf("退出码 %d", code)
	}
	// /24 全无响应：早退后约为预算的 1/3，放宽到 10 秒仅用于兜住挂死。
	if elapsed > 10*time.Second {
		t.Errorf("/24 耗时 %v，疑似挂死", elapsed)
	}
}
