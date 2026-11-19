package storage

import (
	"context"
	"errors"

	"threat-service/internal/model"
)

var (
	ErrNotFound      = errors.New("threat not found")
	ErrAlreadyExists = errors.New("threat already exists")
)

type Storage interface {
	Get(ctx context.Context, md5 string) (model.Threat, error)
	Create(ctx context.Context, t model.Threat) (model.Threat, error)
	Update(ctx context.Context, t model.Threat) (model.Threat, error)
}
