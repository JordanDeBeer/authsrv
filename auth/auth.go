package auth

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type server struct {
	store   UserStore
	router  *mux.Router
	log     *logrus.Logger
	privKey *ecdsa.PrivateKey
}

// New creates a new auth server struct.
func New(r *mux.Router, store UserStore, l *logrus.Logger, k *ecdsa.PrivateKey) *server {
	s := server{router: r, store: store, log: l, privKey: k}
	s.routes()
	return &s
}

func (s *server) jsonResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)

	b, err := json.Marshal(data)
	if err != nil {
		s.jsonResponse(w, map[string]string{"error": "internal server error"}, http.StatusInternalServerError)
	}
	w.Write(b)
}

func GetBearerToken(header string) (string, error) {
	if header == "" {
		return "", fmt.Errorf("An authorization header is required")
	}
	token := strings.Split(header, " ")
	if len(token) != 2 {
		return "", fmt.Errorf("Malformed bearer token")
	}
	return token[1], nil
}

func VerifyJwt(token string, pubKey crypto.PublicKey) (*authsrvClaims, error) {
	jwToken, err := jwt.ParseWithClaims(token, &authsrvClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return pubKey, nil
	})
	if err != nil {
		return &authsrvClaims{}, err
	}
	if !jwToken.Valid {
		return &authsrvClaims{}, fmt.Errorf("Invalid authorization token")
	}
	if jwToken.Claims.(*authsrvClaims).Type != "access" {
		return jwToken.Claims.(*authsrvClaims), fmt.Errorf("Token is not an access token")

	}
	return jwToken.Claims.(*authsrvClaims), nil
}
