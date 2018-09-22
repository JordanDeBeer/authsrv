package auth

import jwt "github.com/dgrijalva/jwt-go"

type user struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type jwtClaims struct {
	ID int64 `json:"id"`
	jwt.StandardClaims
}
