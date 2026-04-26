package main

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web/index.html web/assets/*
var webFS embed.FS

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

	assets, _ := fs.Sub(webFS, "web/assets")
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assets))))
	return mux
}

func serve(address string, mux *http.ServeMux) error {
	return http.ListenAndServe(address, mux)
}

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
