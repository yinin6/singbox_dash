// app.go - 应用入口
//
// 职责：加载持久化状态，启动 HTTP 服务。
// 这是整个 singbox_dash 面板的启动入口，监听本地 8088 端口。
package main

const (
	addr      = "127.0.0.1:8088" // 面板 HTTP 监听地址（仅本地访问）
	stateDir  = "data"            // 状态数据存储目录
	stateFile = "data/state.json" // 状态数据文件路径
)

// store 是全局状态存储实例，在 main 中初始化并加载
var store = &Store{}

func main() {
	// 启动时从 stateFile 加载持久化状态；若文件不存在则生成默认状态
	if err := store.load(); err != nil {
		panic(err)
	}

	// 创建 HTTP 路由并启动服务
	mux := newMux()
	if err := serve(addr, mux); err != nil {
		panic(err)
	}
}
