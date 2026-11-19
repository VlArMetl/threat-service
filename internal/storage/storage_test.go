package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"threat-service/internal/model"
)

func testStorage(t *testing.T, newStore func(t *testing.T) Storage) {
	ctx := context.Background()
	threat := model.Threat{
		MD5:         "D41D8CD98F00B204E9800998ECF8427E",
		Name:        "Trojan.Win32.Generic",
		Severity:    model.SeverityHigh,
		Description: "test",
	}

	t.Run("get missing returns ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Get(ctx, threat.MD5); !errors.Is(err, ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("create then get", func(t *testing.T) {
		s := newStore(t)
		created, err := s.Create(ctx, threat)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if created.MD5 != "d41d8cd98f00b204e9800998ecf8427e" {
			t.Errorf("md5 must be lowercased, got %q", created.MD5)
		}
		if created.CreatedAt.IsZero() || !created.CreatedAt.Equal(created.UpdatedAt) {
			t.Errorf("timestamps not set correctly: %v / %v", created.CreatedAt, created.UpdatedAt)
		}

		got, err := s.Get(ctx, "d41d8cd98f00b204e9800998ecf8427e")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Name != threat.Name || got.Severity != threat.Severity || got.Description != threat.Description {
			t.Errorf("got %+v, want fields of %+v", got, threat)
		}
		if !got.CreatedAt.Equal(created.CreatedAt) {
			t.Errorf("created_at changed: %v != %v", got.CreatedAt, created.CreatedAt)
		}
	})

	t.Run("duplicate create returns ErrAlreadyExists", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Create(ctx, threat); err != nil {
			t.Fatalf("create: %v", err)
		}
		dup := threat
		dup.MD5 = "d41d8cd98f00b204e9800998ecf8427e"
		if _, err := s.Create(ctx, dup); !errors.Is(err, ErrAlreadyExists) {
			t.Fatalf("want ErrAlreadyExists, got %v", err)
		}
	})

	t.Run("update keeps created_at and replaces fields", func(t *testing.T) {
		s := newStore(t)
		created, err := s.Create(ctx, threat)
		if err != nil {
			t.Fatalf("create: %v", err)
		}

		upd := model.Threat{MD5: threat.MD5, Name: "Updated", Severity: model.SeverityLow}
		updated, err := s.Update(ctx, upd)
		if err != nil {
			t.Fatalf("update: %v", err)
		}
		if !updated.CreatedAt.Equal(created.CreatedAt) {
			t.Errorf("created_at changed: %v != %v", updated.CreatedAt, created.CreatedAt)
		}
		if updated.UpdatedAt.Before(created.UpdatedAt) {
			t.Errorf("updated_at went back in time")
		}

		got, err := s.Get(ctx, threat.MD5)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Name != "Updated" || got.Severity != model.SeverityLow || got.Description != "" {
			t.Errorf("update not persisted: %+v", got)
		}
	})

	t.Run("update missing returns ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Update(ctx, threat); !errors.Is(err, ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("concurrent creates", func(t *testing.T) {
		s := newStore(t)
		var wg sync.WaitGroup
		for i := range 50 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				th := threat
				th.MD5 = fmt.Sprintf("%032x", i)
				if _, err := s.Create(ctx, th); err != nil {
					t.Errorf("create %d: %v", i, err)
				}
			}()
		}
		wg.Wait()
		for i := range 50 {
			if _, err := s.Get(ctx, fmt.Sprintf("%032x", i)); err != nil {
				t.Errorf("get %d: %v", i, err)
			}
		}
	})
}

func TestMemoryStorage(t *testing.T) {
	testStorage(t, func(*testing.T) Storage { return NewMemoryStorage() })
}
