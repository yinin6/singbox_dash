// web.go - HTTP 路由注册与静态资源服务
//
// 职责：
//   - newMux() 注册所有 API 路由和前端静态文件路由
//   - serve() 启动 HTTP 服务器
//   - indexHandler 返回前端首页
//   - 使用 Go embed 嵌入 web/ 目录下的前端资源
package main

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web/index.html web/assets/*
var webFS embed.FS // 编译时嵌入前端静态资源

// newMux 创建并配置 HTTP 路由
// 路由清单：
//   /                           → 前端首页
//   /api/state                  → 全局状态 CRUD
//   /api/service                → 创建服务
//   /api/service/{id}           → 删除服务 / Reality 密钥对
//   /api/certificate            → 创建证书
//   /api/certificate/{id}       → 删除证书 / 签发 / 状态 / Reality 密钥对
//   /api/validate/server        → 验证服务端配置
//   /api/runtime/apply          → 应用配置到 sing-box
//   /api/runtime/status         → 查询运行时状态
//   /api/runtime/stop           → 停止 sing-box 进程
//   /export/server.json         → 导出服务端配置
//   /export/client.json         → 导出客户端配置
//   /sub/{token}                → 订阅链接端点
//   /assets/*                   → 前端静态资源
func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/api/state", stateHandler)
	mux.HandleFunc("/api/service", serviceCreateHandler)
	mux.HandleFunc("/api/service/", serviceItemHandler)
	mux.HandleFunc("/api/certificate", certificateCreateHandler)
	mux.HandleFunc("/api/certificate/", certificateItemHandler)
	mux.HandleFunc("/api/validate/server", serverValidateHandler)
	mux.HandleFunc("/api/runtime/apply", runtimeApplyHandler)
	mux.HandleFunc("/api/runtime/status", runtimeStatusHandler)
	mux.HandleFunc("/api/runtime/stop", runtimeStopHandler)
	mux.HandleFunc("/export/server.json", serverConfigHandler)
	mux.HandleFunc("/export/client.json", clientConfigHandler)
	mux.HandleFunc("/sub/", subscriptionHandler)

	// 从嵌入资源中提供前端静态文件 (JS/CSS)
	assets, _ := fs.Sub(webFS, "web/assets")
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assets))))
	return mux
}

// serve 在指定地址上启动 HTTP 服务器
func serve(address string, mux *http.ServeMux) error {
	return http.ListenAndServe(address, mux)
}

// indexHandler 返回前端首页 HTML
// 仅匹配精确路径 "/"，其他路径返回 404
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}
