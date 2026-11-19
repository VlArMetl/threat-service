package storage

import (
	"context"
	"sync"
	"time"

	"threat-service/internal/model"
)

type MemoryStorage struct {
	mu      sync.RWMutex
	threats map[string]model.Threat
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		threats: make(map[string]model.Threat),
	}
}

func (s *MemoryStorage) Get(_ context.Context, md5 string) (model.Threat, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.threats[model.NormalizeMD5(md5)]
	if !ok {
		return model.Threat{}, ErrNotFound
	}
	return t, nil
}

func (s *MemoryStorage) Create(_ context.Context, t model.Threat) (model.Threat, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t.MD5 = model.NormalizeMD5(t.MD5)
	if _, ok := s.threats[t.MD5]; ok {
		return model.Threat{}, ErrAlreadyExists
	}

	now := time.Now().UTC()
	t.CreatedAt = now
	t.UpdatedAt = now
	s.threats[t.MD5] = t
	return t, nil
}

func (s *MemoryStorage) Update(_ context.Context, t model.Threat) (model.Threat, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t.MD5 = model.NormalizeMD5(t.MD5)
	old, ok := s.threats[t.MD5]
	if !ok {
		return model.Threat{}, ErrNotFound
	}
	t.CreatedAt = old.CreatedAt
	t.UpdatedAt = time.Now().UTC()
	s.threats[t.MD5] = t
	return t, nil
}
