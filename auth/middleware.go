package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

func (s *server) ApplyMw(h http.Handler) http.Handler {
	return s.requestIDMw(h)
}

func (s *server) AuthnMw(fn http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			bearerToken := strings.Split(authHeader, " ")
			if len(bearerToken) == 2 {
				token, err := jwt.ParseWithClaims(bearerToken[1], &jwtClaims{}, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
						return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
					}

					return s.privKey.Public(), nil
				})
				if err != nil {
					s.log.Infof("Invalid token. Err: %v", err)
					s.jsonResponse(w, map[string]string{"error": "invalid token"}, http.StatusForbidden)
					return
				}
				if !token.Valid {
					s.log.Infof("Invalid token. Err: %v", err)
					data := map[string]string{"error": "invalid token"}
					s.jsonResponse(w, data, http.StatusForbidden)
				} else {
					s.log.Debugf("Valid token for")
					fn.ServeHTTP(w, r)
				}
			} else {
				s.jsonResponse(w, map[string]string{"error": "invalid token"}, http.StatusForbidden)
			}
		} else {
			s.jsonResponse(w, map[string]string{"error": "no authorization header"}, http.StatusForbidden)
		}
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
