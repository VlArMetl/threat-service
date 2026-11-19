package storage

import (
	"context"
	"os"
	"testing"
)

func TestPostgresStorage(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	testStorage(t, func(t *testing.T) Storage {
		ctx := context.Background()
		s, err := NewPostgresStorage(ctx, dsn)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		t.Cleanup(s.Close)
		if _, err := s.pool.Exec(ctx, "TRUNCATE threats"); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return s
	})
}
