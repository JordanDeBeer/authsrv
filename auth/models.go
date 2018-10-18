package auth

import (
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

type user struct {
	UID      int64  `json:"uid"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type authsrvClaims struct {
	UID  int64  `json:"uid"`
	Type string `json:"type"`
	jwt.StandardClaims
}

func (s *server) newAuthsrvToken(t string, u user) (string, error) {
	var expires int64
	switch {
	case t == "refresh":
		expires = time.Now().Add(time.Hour * 24).Unix()
	case t == "access":
		expires = time.Now().Add(time.Minute * 5).Unix()
	default:
		return "", fmt.Errorf("Token type not recognized")
	}
	claims := authsrvClaims{
		u.UID,
		t,
		jwt.StandardClaims{
			Id:        uuid.New().String(),
			Issuer:    "authsrv",
			Audience:  "api.jordandebeer.com",
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: expires,
		},
	}
	//token, err := SignJwt(claims, s.privKey)
	token := jwt.NewWithClaims(jwt.SigningMethodES512, claims)
	ss, err := token.SignedString(s.privKey)
	if err != nil {
		return "", fmt.Errorf("Error signing token. Err: %v", err)
	}
	return ss, nil
}
