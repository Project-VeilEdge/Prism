package web

import "net/http"

// Handler serves pre-generated camouflage pages with security headers.
type Handler struct {
	gen *Generator
}

// NewHandler creates a Handler backed by the given Generator.
func NewHandler(gen *Generator) *Handler {
	return &Handler{gen: gen}
}

// ServeHTTP serves the cached page for the request path, or a styled 404.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")

	page, ok := h.gen.pages[r.URL.Path]
	if !ok {
		page = h.gen.pages["404"]
	}
	w.Header().Set("Content-Type", page.ContentType)
	w.WriteHeader(page.StatusCode)
	w.Write(page.Body)
}
