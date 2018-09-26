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
		u, err := s.store.GetUserByUsername(reqUser.Username)
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
		}

		// Setup claims
		claims := jwt.MapClaims{
			"id":  u.ID,
			"aud": "api.jordandebeer.com",
			"exp": time.Now().Add(time.Minute * 5).Unix(),
			"iss": "authsrv",
			"iat": time.Now().Unix(),
		}

		// Create token
		token, err := SignJwt(claims, s.privKey)
		if err != nil {
			s.log.Errorf("Error signing token. Err: %v", err)
			s.jsonResponse(w, map[string]string{"error": "err"}, http.StatusInternalServerError)
		}
		s.logEntry(r).Infof("Logged in: %v", reqUser.Username)

		m := map[string]string{
			"username":   u.Username,
			"access_key": token,
		}

		s.jsonResponse(w, m, http.StatusOK)
	})
}
