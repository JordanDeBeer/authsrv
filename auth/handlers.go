package auth

// handlers
import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

func (s *server) rootHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{"ping": "pong"}
		s.logEntry(r).Info("ping pong!")
		s.jsonResponse(w, data, http.StatusOK)
	})
}

func (s *server) infoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.
	})
}

func (s *server) loginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.logEntry(r).Debug("calling loginHandler()")
		var reqUser user
		err := json.NewDecoder(r.Body).Decode(&reqUser)
		if err != nil {
			s.logEntry(r).Errorf("Error decoding json. Error: %v", err)
			s.jsonResponse(w, map[string]string{"error": "could not parse request"}, http.StatusBadRequest)
			return
		}

		s.logEntry(r).Debugf("Getting user by username: %v", reqUser.Username)
		u, err := s.getUserByUsername(reqUser.Username)
		if err != nil {
			switch err {
			case sql.ErrNoRows:
				s.logEntry(r).Infof("Could not find User: %v", err)
				s.jsonResponse(w, map[string]string{"error": "could not find user"}, http.StatusUnauthorized)
			default:
				s.logEntry(r).Errorf("Database error: %+v", err)
				s.jsonResponse(w, map[string]string{"error": "internal server error"}, http.StatusInternalServerError)
			}
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(reqUser.Password))
		if err != nil {
			s.logEntry(r).Infof("Failed login for user: %v", reqUser.Username)
			s.jsonResponse(w, map[string]string{"error": "failed to authenticate"}, http.StatusUnauthorized)
			return
		}

		// Setup claims
		claims := jwtClaims{
			u.ID,
			jwt.StandardClaims{
				Audience:  "api.jordandebeer.com",
				ExpiresAt: time.Now().Add(time.Minute * 5).Unix(),
				Issuer:    "authsrv",
				IssuedAt:  time.Now().Unix(),
			},
		}

		// Create token
		token := jwt.NewWithClaims(jwt.SigningMethodES512, claims)

		// Create private key
		ss, err := token.SignedString(s.privKey)
		if err != nil {
			s.logEntry(r).Errorf("Error signing token: %v", err)
			s.jsonResponse(w, map[string]string{"error": "internal Server Error"}, http.StatusInternalServerError)
		}
		s.logEntry(r).Infof("Logged in: %v", reqUser.Username)

		m := map[string]interface{}{
			"username":   u.Username,
			"access_key": ss,
		}

		s.jsonResponse(w, m, http.StatusOK)
	})
}
