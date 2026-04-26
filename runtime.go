// runtime.go - sing-box 运行时管理
//
// 职责：
//   - applyRuntimeConfig() 将服务端配置写入文件、校验、重启 sing-box
//   - startRuntime() 启动 sing-box 进程（后台运行，日志追加写入）
//   - stopRuntime() 停止 sing-box 进程（SIGINT 优雅停止，超时则 SIGKILL）
//   - runtimeStatus() 查询运行时状态（进程是否存活、PID、日志尾部）
//   - resolveSingBoxPath() 解析 sing-box 二进制路径
//   - findProcessesByConfig() 通过 /proc 扫描匹配配置文件的进程
//   - tailFile() 读取文件末尾内容
//   - HTTP 处理器：runtimeApplyHandler / runtimeStatusHandler / runtimeStopHandler
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// runtimeApplyHandler 应用配置到 sing-box（POST /api/runtime/apply）
// 流程：写入配置 → 校验配置 → （可选）停止旧进程 → 启动新进程
func runtimeApplyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, applyRuntimeConfig(store.snapshot()))
}

// runtimeStatusHandler 查询 sing-box 运行时状态（GET /api/runtime/status）
func runtimeStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, runtimeStatus(store.snapshot().Panel))
}

// runtimeStopHandler 停止 sing-box 进程（POST /api/runtime/stop）
func runtimeStopHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, stopRuntime(store.snapshot().Panel))
}

// applyRuntimeConfig 应用运行时配置的核心流程
// 1. 生成并写入服务端配置文件
// 2. 调用 sing-box check 校验配置合法性
// 3. 若 AutoRestart=true，则停止旧进程并启动新进程
// 4. 若 AutoRestart=false，仅写入和校验
func applyRuntimeConfig(state AppState) map[string]any {
	panel := state.Panel
	cfg := buildServerConfig(state)

	// 步骤1：写入配置文件
	if err := writeConfigFile(panel.RuntimeConfigPath, cfg); err != nil {
		return map[string]any{"ok": false, "stage": "write", "message": err.Error()}
	}

	// 步骤2：校验配置
	check := checkSingBoxConfig(panel.SingBoxPath, panel.RuntimeConfigPath)
	if ok, _ := check["ok"].(bool); !ok {
		check["stage"] = "check"
		check["config_path"] = panel.RuntimeConfigPath
		return check
	}

	// 步骤3：根据 AutoRestart 设置决定是否重启
	if panel.AutoRestart {
		stopRuntime(panel)
		start := startRuntime(panel)
		start["stage"] = "start"
		start["config_path"] = panel.RuntimeConfigPath
		return start
	}

	// AutoRestart=false：仅写入和校验，返回当前状态
	status := runtimeStatus(panel)
	status["ok"] = true
	status["stage"] = "write"
	status["message"] = "config written and validated; auto restart is disabled"
	status["config_path"] = panel.RuntimeConfigPath
	return status
}

// writeConfigFile 将配置写入指定路径的 JSON 文件
// 自动创建父目录，文件权限 0600
func writeConfigFile(path string, cfg map[string]any) error {
	path = runtimeFilePath(path)
	if path == "" {
		return errors.New("config path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// checkSingBoxConfig 调用 sing-box check -c <configPath> 验证配置合法性
// 超时 30 秒
func checkSingBoxConfig(binPath string, configPath string) map[string]any {
	bin, err := resolveSingBoxPath(binPath)
	if err != nil {
		return map[string]any{"ok": false, "message": err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "check", "-c", configPath)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return map[string]any{"ok": false, "message": "sing-box check timed out", "output": string(out)}
	}
	if err != nil {
		return map[string]any{"ok": false, "message": err.Error(), "output": string(out)}
	}
	return map[string]any{"ok": true, "message": "sing-box check passed", "output": string(out)}
}

// startRuntime 启动 sing-box 进程
// 1. 解析二进制路径
// 2. 创建 PID 和日志文件的目录
// 3. 以后台模式启动 sing-box run -c <config>
// 4. 将 PID 写入文件
// 5. 等待 300ms 后检查进程是否仍存活（防止立即退出）
func startRuntime(panel PanelSettings) map[string]any {
	bin, err := resolveSingBoxPath(panel.SingBoxPath)
	if err != nil {
		return map[string]any{"ok": false, "message": err.Error()}
	}
	pidPath := runtimeFilePath(panel.RuntimePIDPath)
	logPath := runtimeFilePath(panel.RuntimeLogPath)
	configPath := runtimeFilePath(panel.RuntimeConfigPath)

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(pidPath), 0o700); err != nil {
		return map[string]any{"ok": false, "message": err.Error()}
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return map[string]any{"ok": false, "message": err.Error()}
	}

	// 打开日志文件（追加模式）
	logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return map[string]any{"ok": false, "message": err.Error()}
	}

	// 启动 sing-box 进程，stdout/stderr 重定向到日志文件
	cmd := exec.Command(bin, "run", "-c", configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return map[string]any{"ok": false, "message": err.Error()}
	}
	_ = logFile.Close()

	// 写入 PID 文件
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		_ = cmd.Process.Kill()
		return map[string]any{"ok": false, "message": err.Error()}
	}
	_ = cmd.Process.Release() // 释放进程引用，让 sing-box 在后台运行

	// 短暂等待后检查进程是否存活
	time.Sleep(300 * time.Millisecond)
	status := runtimeStatus(panel)
	if running, _ := status["running"].(bool); !running {
		status["ok"] = false
		status["message"] = "sing-box started but exited immediately; check runtime log"
		status["log_tail"] = tailFile(logPath, 4000)
		return status
	}
	status["ok"] = true
	status["message"] = "sing-box is running"
	return status
}

// stopRuntime 停止 sing-box 进程
// 1. 查找所有关联的 PID（PID 文件 + /proc 扫描）
// 2. 发送 SIGINT 优雅停止
// 3. 最多等待 2 秒，超时则 SIGKILL 强制杀死
// 4. 清理 PID 文件
func stopRuntime(panel PanelSettings) map[string]any {
	pids := runtimePIDs(panel)
	if len(pids) == 0 {
		return map[string]any{"ok": true, "running": false, "message": "sing-box is not managed by this panel"}
	}
	for _, pid := range pids {
		proc, err := os.FindProcess(pid)
		if err == nil {
			_ = proc.Signal(os.Interrupt) // 发送 SIGINT
			// 等待进程退出（最多 2 秒）
			for i := 0; i < 20; i++ {
				if !processRunning(pid) {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			// 如果进程仍在运行，强制杀死
			if processRunning(pid) {
				_ = proc.Kill()
			}
		}
	}
	_ = os.Remove(runtimeFilePath(panel.RuntimePIDPath))
	return map[string]any{"ok": true, "running": false, "pids": pids, "message": "sing-box stopped"}
}

// runtimeStatus 查询 sing-box 运行时状态
// 返回：是否运行、PID、配置路径、日志路径、日志尾部内容
func runtimeStatus(panel PanelSettings) map[string]any {
	pidPath := runtimeFilePath(panel.RuntimePIDPath)
	configPath := runtimeFilePath(panel.RuntimeConfigPath)
	logPath := runtimeFilePath(panel.RuntimeLogPath)
	pids := runtimePIDs(panel)
	if len(pids) == 0 {
		// 进程不存在，清理残留的 PID 文件
		_ = os.Remove(pidPath)
		return map[string]any{"running": false, "message": "not running", "config_path": configPath, "log_path": logPath, "log_tail": tailFile(logPath, 4000)}
	}
	return map[string]any{"running": true, "pid": pids[0], "pids": pids, "message": "running", "config_path": configPath, "log_path": logPath, "log_tail": tailFile(logPath, 4000)}
}

// resolveSingBoxPath 解析 sing-box 二进制路径
// 如果路径包含目录分隔符或以 . 开头，视为相对/绝对路径，直接检查文件是否存在
// 否则通过 PATH 查找
func resolveSingBoxPath(path string) (string, error) {
	if path == "" {
		path = "sing-box"
	}
	if strings.ContainsRune(path, filepath.Separator) || strings.HasPrefix(path, ".") {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path, nil
		}
		return "", fmt.Errorf("sing-box binary not found at %s", path)
	}
	bin, err := exec.LookPath(path)
	if err != nil {
		return "", fmt.Errorf("%s command not found", path)
	}
	return bin, nil
}

// readRuntimePID 从 PID 文件读取进程号
func readRuntimePID(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// runtimePIDs 获取所有与当前面板关联的 sing-box 进程 PID
// 两个来源：1) PID 文件中记录的 PID；2) /proc 扫描匹配的 PID
func runtimePIDs(panel PanelSettings) []int {
	seen := map[int]bool{}
	pids := []int{}
	pidPath := runtimeFilePath(panel.RuntimePIDPath)
	configPath := runtimeFilePath(panel.RuntimeConfigPath)

	// 来源1：PID 文件
	if pid, err := readRuntimePID(pidPath); err == nil && processRunning(pid) {
		seen[pid] = true
		pids = append(pids, pid)
	}
	// 来源2：扫描 /proc 匹配配置文件路径的进程
	for _, pid := range findProcessesByConfig(configPath) {
		if !seen[pid] && processRunning(pid) {
			seen[pid] = true
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids
}

// findProcessesByConfig 扫描 /proc 目录，查找使用指定配置文件的 sing-box 进程
// 匹配条件：cmdline 包含 "sing-box" + " run " + 配置文件路径
func findProcessesByConfig(configPath string) []int {
	matches := []int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return matches // 非 Linux 系统可能没有 /proc
	}
	absConfig, _ := filepath.Abs(configPath)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // 非数字目录名，跳过
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil || len(data) == 0 {
			continue
		}
		// /proc/pid/cmdline 中参数以 \0 分隔，替换为空格便于匹配
		cmdline := strings.ReplaceAll(string(data), "\x00", " ")
		if strings.Contains(cmdline, "sing-box") &&
			strings.Contains(cmdline, " run ") &&
			(strings.Contains(cmdline, configPath) || (absConfig != "" && strings.Contains(cmdline, absConfig))) {
			matches = append(matches, pid)
		}
	}
	return matches
}

// processRunning 检查指定 PID 的进程是否仍在运行
// 优先读取 /proc/{pid}/status 判断（排除僵尸进程）
// 回退到 signal(nil) 方式检测
func processRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	// 尝试从 /proc 读取进程状态
	status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "State:") {
				// 僵尸进程不算运行中
				return !strings.Contains(line, "Z (zombie)")
			}
		}
		return true
	}
	// 回退：通过信号检测进程是否存在
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(nil) == nil
}

// tailFile 读取文件的最后 limit 字节内容
// 用于获取 sing-box 运行日志的尾部
func tailFile(path string, limit int) string {
	if path == "" || limit <= 0 {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if len(data) > limit {
		data = data[len(data)-limit:]
	}
	return string(data)
}
