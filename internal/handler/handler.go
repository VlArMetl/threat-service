package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"threat-service/internal/api"
	"threat-service/internal/model"
	"threat-service/internal/respond"
	"threat-service/internal/storage"
)

const MaxBodySize = 1024 * 1024

type Handler struct {
	storage storage.Storage
}

func New(s storage.Storage) *Handler {
	return &Handler{storage: s}
}

func (h *Handler) Routes() http.Handler {
	return api.HandlerWithOptions(h, api.StdHTTPServerOptions{
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			respond.Error(w, http.StatusBadRequest, "Invalid request parameters", err.Error())
		},
	})
}

func (h *Handler) GetInfoByMd5(w http.ResponseWriter, r *http.Request, md5 string) {
	if err := model.ValidateMD5(md5); err != nil {
		respond.Error(w, http.StatusBadRequest, "Invalid MD5", err.Error())
		return
	}

	t, err := h.storage.Get(r.Context(), md5)
	if errors.Is(err, storage.ErrNotFound) {
		respond.Error(w, http.StatusNotFound, "Threat not found", fmt.Sprintf("No threat with MD5 %s found", md5))
		return
	}
	if err != nil {
		internalError(w, "get threat", md5, err)
		return
	}
	respond.JSON(w, http.StatusOK, toResponse(t))
}

func (h *Handler) CreateThreat(w http.ResponseWriter, r *http.Request) {
	var req api.ThreatCreateRequest
	if err := decodeJSON(w, r, &req); err != nil {
		respond.Error(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	t := model.Threat{
		MD5:         req.Md5,
		Name:        req.Name,
		Severity:    model.Severity(req.Severity),
		Description: deref(req.Description),
	}
	if err := t.Validate(); err != nil {
		respond.Error(w, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	created, err := h.storage.Create(r.Context(), t)
	if errors.Is(err, storage.ErrAlreadyExists) {
		respond.Error(w, http.StatusConflict, "Threat already exists", fmt.Sprintf("Threat with MD5 %s already exists", t.MD5))
		return
	}
	if err != nil {
		internalError(w, "create threat", t.MD5, err)
		return
	}
	respond.JSON(w, http.StatusCreated, toResponse(created))
}

func (h *Handler) UpdateThreat(w http.ResponseWriter, r *http.Request, md5 string) {
	if err := model.ValidateMD5(md5); err != nil {
		respond.Error(w, http.StatusBadRequest, "Invalid MD5", err.Error())
		return
	}

	var req api.ThreatUpdateRequest
	if err := decodeJSON(w, r, &req); err != nil {
		respond.Error(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	t := model.Threat{
		MD5:         md5,
		Name:        req.Name,
		Severity:    model.Severity(req.Severity),
		Description: deref(req.Description),
	}
	if err := t.Validate(); err != nil {
		respond.Error(w, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	updated, err := h.storage.Update(r.Context(), t)
	if errors.Is(err, storage.ErrNotFound) {
		respond.Error(w, http.StatusNotFound, "Threat not found", fmt.Sprintf("Threat with MD5 %s not found", md5))
		return
	}
	if err != nil {
		internalError(w, "update threat", md5, err)
		return
	}
	respond.JSON(w, http.StatusOK, toResponse(updated))
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodySize)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func internalError(w http.ResponseWriter, op, md5 string, err error) {
	log.Printf("%s %s: %v", op, md5, err)
	respond.Error(w, http.StatusInternalServerError, "Internal server error", "")
}

func toResponse(t model.Threat) api.ThreatResponse {
	resp := api.ThreatResponse{
		Md5:       t.MD5,
		Name:      t.Name,
		Severity:  api.Severity(t.Severity),
		CreatedAt: t.CreatedAt,
		UpdatedAt: t.UpdatedAt,
	}
	if t.Description != "" {
		resp.Description = &t.Description
	}
	return resp
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
