package main

import (
	"errors"
	"os"
	"time"
)

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := os.Stat(stateFile); errors.Is(err, os.ErrNotExist) {
		s.state = defaultState()
		return s.saveLocked()
	}

	data, err := os.ReadFile(stateFile)
	if err != nil {
		return err
	}
	if err := unmarshalState(data, &s.state); err != nil {
		return err
	}
	normalizeState(&s.state)
	return nil
}

func (s *Store) snapshot() AppState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneState(s.state)
}

func (s *Store) replace(next AppState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalizeState(&next)
	next.UpdatedAt = time.Now()
	s.state = next
	return s.saveLocked()
}

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

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return err
	}
	data, err := marshalState(s.state)
	if err != nil {
		return err
	}
	return os.WriteFile(stateFile, data, 0o600)
}
