// sync_alias.go - 类型别名
//
// 职责：为 sync.RWMutex 定义简短的包内别名。
// 全局 Store 使用 RWMutex 保护并发读写状态。
package main

import "sync"

// RWMutex 是 sync.RWMutex 的别名，供 store 等模块直接使用
type RWMutex = sync.RWMutex
