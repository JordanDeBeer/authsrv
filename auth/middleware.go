package auth

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

func (s *server) AuthnMw(fn http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearerToken, err := GetBearerToken(r.Header.Get("authorization"))
		if err != nil {
			s.jsonResponse(w, map[string]error{"error": err}, http.StatusForbidden)
		}
		_, err = VerifyJwt(bearerToken, s.privKey.Public())
		if err != nil {
			s.logEntry(r).Errorf("Error verifying token: %v", err)
			s.jsonResponse(w, map[string]error{"error": err}, http.StatusForbidden)
		}
		s.log.Debugf("Valid token for user")
		fn.ServeHTTP(w, r)
	})
}

func (s *server) requestIDMw(fn http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = uuid.New().String()
		}
		w.Header().Set("X-Request-ID", reqID)
		ctx := context.WithValue(r.Context(), "request_id", reqID)

		fn.ServeHTTP(w, r.WithContext(ctx))
	})
}
