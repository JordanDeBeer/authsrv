package auth

// handlers
import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func (s *server) rootHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{"ping": "pong"}
		s.logEntry(r).Info("ping pong!")
		s.jsonResponse(w, data, http.StatusOK)
		return
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
				return
			default:
				s.logEntry(r).Errorf("Database error: %+v", err)
				s.jsonResponse(w, map[string]string{"error": "internal server error"}, http.StatusInternalServerError)
				return
			}
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(reqUser.Password))
		if err != nil {
			s.logEntry(r).Infof("Failed login for user: %v", reqUser.Username)
			s.jsonResponse(w, map[string]string{"error": "failed to authenticate"}, http.StatusUnauthorized)
			return
		}

		// Create token
		access_token, err := s.newAuthsrvToken("access", u)
		if err != nil {
			s.log.Errorf("Error getting access token. Err: %v", err)
			s.jsonResponse(w, map[string]string{"error": "err"}, http.StatusInternalServerError)
			return
		}

		refresh_token, err := s.newAuthsrvToken("refresh", u)
		if err != nil {
			s.log.Errorf("Error getting refresh token. Err: %v", err)
			s.jsonResponse(w, map[string]string{"error": "err"}, http.StatusInternalServerError)
			return
		}

		s.logEntry(r).Infof("Logged in: %v", reqUser.Username)

		m := map[string]string{
			"username":      u.Username,
			"access_token":  access_token,
			"refresh_token": refresh_token,
		}

		s.jsonResponse(w, m, http.StatusOK)
		return
	})
}

func (s *server) refreshHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.logEntry(r).Debug("calling refreshHandler()")
		bearerToken, err := GetBearerToken(r.Header.Get("authorization"))
		if err != nil {
			s.logEntry(r).Errorf("Error getting token: %v", err)
			s.jsonResponse(w, map[string]error{"error": err}, http.StatusForbidden)
			return
		}
		token, err := VerifyJwt(bearerToken, s.privKey.Public())
		if err.Error() != "Token is not an access token" {
			s.logEntry(r).Errorf("Error verifying token: %v", err)
			s.jsonResponse(w, map[string]string{"error": "error verifying token"}, http.StatusForbidden)
			return
		}
		if token.Type != "refresh" {
			s.logEntry(r).Error("Error verifying refresh token.")
			s.jsonResponse(w, map[string]string{"error": "invalid token"}, http.StatusForbidden)
			return
		}
		fmt.Printf("%+v", token)

		// check revocation
		revoked, err := s.store.CheckTokenRevocation(token.Id)
		if err != nil {
			s.logEntry(r).Error("Error checking token revocation, %v", err)
			s.jsonResponse(w, map[string]string{"error": "error checking token"}, http.StatusInternalServerError)
		}
		if revoked {
			s.logEntry(r).Error("Revoked token")
			s.jsonResponse(w, map[string]string{"error": "revoked token"}, http.StatusForbidden)
			return
		}

		user, _ := s.store.GetUserByUID(token.UID)
		access_token, _ := s.newAuthsrvToken("access", user)
		m := map[string]string{
			"access_token": access_token,
		}
		s.jsonResponse(w, m, http.StatusOK)
	})
}
