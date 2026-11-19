package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"threat-service/internal/model"
)

const schema = `
CREATE TABLE IF NOT EXISTS threats (
	md5         CHAR(32)    PRIMARY KEY,
	name        TEXT        NOT NULL,
	severity    TEXT        NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
	description TEXT        NOT NULL DEFAULT '',
	created_at  TIMESTAMPTZ NOT NULL,
	updated_at  TIMESTAMPTZ NOT NULL
)`

type PostgresStorage struct {
	pool *pgxpool.Pool
}

func NewPostgresStorage(ctx context.Context, dsn string) (*PostgresStorage, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &PostgresStorage{pool: pool}, nil
}

func (s *PostgresStorage) Close() {
	s.pool.Close()
}

func (s *PostgresStorage) Get(ctx context.Context, md5 string) (model.Threat, error) {
	var t model.Threat
	err := s.pool.QueryRow(ctx,
		`SELECT md5, name, severity, description, created_at, updated_at
		 FROM threats WHERE md5 = $1`,
		model.NormalizeMD5(md5),
	).Scan(&t.MD5, &t.Name, &t.Severity, &t.Description, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Threat{}, ErrNotFound
	}
	if err != nil {
		return model.Threat{}, fmt.Errorf("select threat: %w", err)
	}
	return toUTC(t), nil
}

func (s *PostgresStorage) Create(ctx context.Context, t model.Threat) (model.Threat, error) {
	t.MD5 = model.NormalizeMD5(t.MD5)
	now := currentTime()
	t.CreatedAt = now
	t.UpdatedAt = now

	var inserted string
	err := s.pool.QueryRow(ctx,
		`INSERT INTO threats (md5, name, severity, description, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (md5) DO NOTHING
		 RETURNING md5`,
		t.MD5, t.Name, t.Severity, t.Description, t.CreatedAt, t.UpdatedAt,
	).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Threat{}, ErrAlreadyExists
	}
	if err != nil {
		return model.Threat{}, fmt.Errorf("insert threat: %w", err)
	}
	return t, nil
}

func (s *PostgresStorage) Update(ctx context.Context, t model.Threat) (model.Threat, error) {
	t.MD5 = model.NormalizeMD5(t.MD5)
	t.UpdatedAt = currentTime()

	err := s.pool.QueryRow(ctx,
		`UPDATE threats
		 SET name = $2, severity = $3, description = $4, updated_at = $5
		 WHERE md5 = $1
		 RETURNING created_at`,
		t.MD5, t.Name, t.Severity, t.Description, t.UpdatedAt,
	).Scan(&t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Threat{}, ErrNotFound
	}
	if err != nil {
		return model.Threat{}, fmt.Errorf("update threat: %w", err)
	}
	return toUTC(t), nil
}

func currentTime() time.Time {
	return time.Now().UTC().Truncate(time.Microsecond)
}

func toUTC(t model.Threat) model.Threat {
	t.CreatedAt = t.CreatedAt.UTC()
	t.UpdatedAt = t.UpdatedAt.UTC()
	return t
}
