package respond

import (
	"encoding/json"
	"log"
	"net/http"

	"threat-service/internal/api"
)

func JSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("failed to encode JSON response: %v", err)
	}
}

func Error(w http.ResponseWriter, status int, message, details string) {
	resp := api.ErrorResponse{Message: message}
	if details != "" {
		resp.Details = &details
	}
	JSON(w, status, resp)
}
