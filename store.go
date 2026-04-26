// store.go - 状态持久化与读写管理
//
// 职责：
//   - load() 从磁盘加载状态文件，不存在则生成默认状态
//   - snapshot() 获取当前状态的快照（只读，RLock 保护）
//   - replace() 整体替换状态并持久化
//   - mutate() 事务性修改状态：克隆 → 修改 → 规范化 → 持久化
//   - saveLocked() 内部方法，将状态写入磁盘（需持有写锁）
package main

import (
	"errors"
	"os"
	"time"
)

// load 从 stateFile 加载应用状态
// 如果文件不存在，则生成默认状态并写入磁盘
func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := os.Stat(stateFile); errors.Is(err, os.ErrNotExist) {
		// 首次运行：生成默认状态并保存
		s.state = defaultState()
		return s.saveLocked()
	}

	// 读取并反序列化状态文件
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return err
	}
	if err := unmarshalState(data, &s.state); err != nil {
		return err
	}
	// 填充可能缺失的字段（兼容旧版本状态文件）
	normalizeState(&s.state)
	return nil
}

// snapshot 返回当前状态的深拷贝快照（只读操作，使用 RLock）
func (s *Store) snapshot() AppState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneState(s.state)
}

// replace 用新的状态整体替换当前状态，规范化后持久化
func (s *Store) replace(next AppState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalizeState(&next)
	next.UpdatedAt = time.Now()
	s.state = next
	return s.saveLocked()
}

// mutate 事务性地修改状态：
// 1. 克隆当前状态
// 2. 在克隆副本上执行修改函数
// 3. 规范化并持久化
// 如果修改函数返回错误，则不做任何变更
func (s *Store) mutate(fn func(*AppState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	if err := fn(&next); err != nil {
		return err
	}
	normalizeState(&next)
	next.UpdatedAt = time.Now()
	s.state = next
	return s.saveLocked()
}

// saveLocked 将当前状态序列化并写入磁盘（调用时需已持有写锁）
func (s *Store) saveLocked() error {
	// 确保状态目录存在
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return err
	}
	data, err := marshalState(s.state)
	if err != nil {
		return err
	}
	// 文件权限 0600：仅 owner 可读写，保护敏感配置
	return os.WriteFile(stateFile, data, 0o600)
}
