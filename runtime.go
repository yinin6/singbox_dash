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

func runtimeApplyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, applyRuntimeConfig(store.snapshot()))
}

func runtimeStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, runtimeStatus(store.snapshot().Panel))
}

func runtimeStopHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, stopRuntime(store.snapshot().Panel))
}

func applyRuntimeConfig(state AppState) map[string]any {
	panel := state.Panel
	cfg := buildServerConfig(state)
	if err := writeConfigFile(panel.RuntimeConfigPath, cfg); err != nil {
		return map[string]any{"ok": false, "stage": "write", "message": err.Error()}
	}
	check := checkSingBoxConfig(panel.SingBoxPath, panel.RuntimeConfigPath)
	if ok, _ := check["ok"].(bool); !ok {
		check["stage"] = "check"
		check["config_path"] = panel.RuntimeConfigPath
		return check
	}
	if panel.AutoRestart {
		stopRuntime(panel)
		start := startRuntime(panel)
		start["stage"] = "start"
		start["config_path"] = panel.RuntimeConfigPath
		return start
	}
	status := runtimeStatus(panel)
	status["ok"] = true
	status["stage"] = "write"
	status["message"] = "config written and validated; auto restart is disabled"
	status["config_path"] = panel.RuntimeConfigPath
	return status
}

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

func startRuntime(panel PanelSettings) map[string]any {
	bin, err := resolveSingBoxPath(panel.SingBoxPath)
	if err != nil {
		return map[string]any{"ok": false, "message": err.Error()}
	}
	pidPath := runtimeFilePath(panel.RuntimePIDPath)
	logPath := runtimeFilePath(panel.RuntimeLogPath)
	configPath := runtimeFilePath(panel.RuntimeConfigPath)
	if err := os.MkdirAll(filepath.Dir(pidPath), 0o700); err != nil {
		return map[string]any{"ok": false, "message": err.Error()}
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return map[string]any{"ok": false, "message": err.Error()}
	}
	logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return map[string]any{"ok": false, "message": err.Error()}
	}
	cmd := exec.Command(bin, "run", "-c", configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return map[string]any{"ok": false, "message": err.Error()}
	}
	_ = logFile.Close()
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		_ = cmd.Process.Kill()
		return map[string]any{"ok": false, "message": err.Error()}
	}
	_ = cmd.Process.Release()
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

func stopRuntime(panel PanelSettings) map[string]any {
	pids := runtimePIDs(panel)
	if len(pids) == 0 {
		return map[string]any{"ok": true, "running": false, "message": "sing-box is not managed by this panel"}
	}
	for _, pid := range pids {
		proc, err := os.FindProcess(pid)
		if err == nil {
			_ = proc.Signal(os.Interrupt)
			for i := 0; i < 20; i++ {
				if !processRunning(pid) {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if processRunning(pid) {
				_ = proc.Kill()
			}
		}
	}
	_ = os.Remove(runtimeFilePath(panel.RuntimePIDPath))
	return map[string]any{"ok": true, "running": false, "pids": pids, "message": "sing-box stopped"}
}

func runtimeStatus(panel PanelSettings) map[string]any {
	pidPath := runtimeFilePath(panel.RuntimePIDPath)
	configPath := runtimeFilePath(panel.RuntimeConfigPath)
	logPath := runtimeFilePath(panel.RuntimeLogPath)
	pids := runtimePIDs(panel)
	if len(pids) == 0 {
		_ = os.Remove(pidPath)
		return map[string]any{"running": false, "message": "not running", "config_path": configPath, "log_path": logPath, "log_tail": tailFile(logPath, 4000)}
	}
	return map[string]any{"running": true, "pid": pids[0], "pids": pids, "message": "running", "config_path": configPath, "log_path": logPath, "log_tail": tailFile(logPath, 4000)}
}

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

func readRuntimePID(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func runtimePIDs(panel PanelSettings) []int {
	seen := map[int]bool{}
	pids := []int{}
	pidPath := runtimeFilePath(panel.RuntimePIDPath)
	configPath := runtimeFilePath(panel.RuntimeConfigPath)
	if pid, err := readRuntimePID(pidPath); err == nil && processRunning(pid) {
		seen[pid] = true
		pids = append(pids, pid)
	}
	for _, pid := range findProcessesByConfig(configPath) {
		if !seen[pid] && processRunning(pid) {
			seen[pid] = true
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids
}

func findProcessesByConfig(configPath string) []int {
	matches := []int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return matches
	}
	absConfig, _ := filepath.Abs(configPath)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil || len(data) == 0 {
			continue
		}
		cmdline := strings.ReplaceAll(string(data), "\x00", " ")
		if strings.Contains(cmdline, "sing-box") &&
			strings.Contains(cmdline, " run ") &&
			(strings.Contains(cmdline, configPath) || (absConfig != "" && strings.Contains(cmdline, absConfig))) {
			matches = append(matches, pid)
		}
	}
	return matches
}

func processRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "State:") {
				return !strings.Contains(line, "Z (zombie)")
			}
		}
		return true
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(nil) == nil
}

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
