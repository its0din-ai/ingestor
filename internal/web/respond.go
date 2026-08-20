package web

import (
	"encoding/json"
	"net/http"
)

type ErrorResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
