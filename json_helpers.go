// json_helpers.go - JSON 序列化辅助函数
//
// 职责：提供 AppState 的 JSON 编解码封装，方便统一序列化格式（缩进输出）。
package main

import "encoding/json"

// marshalState 将 AppState 序列化为带缩进的 JSON 字节切片，用于持久化存储
func marshalState(state AppState) ([]byte, error) {
	return json.MarshalIndent(state, "", "  ")
}

// unmarshalState 从 JSON 字节切片反序列化为 AppState，用于加载状态文件
func unmarshalState(data []byte, state *AppState) error {
	return json.Unmarshal(data, state)
}
