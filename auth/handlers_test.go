package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var s server

type testStore struct{}

func (t testStore) GetUserByUsername(un string) (user, error) {
	// Mock a user.  Password is bcrypt: "test"
	if un == "jordan" {
		return user{ID: 1, Username: "jordan", Password: "$2y$12$HbdwCNzjxeHijMGzzatkvOmCw9sO1d5iSwDgmGacng9JjZp7R.Dgm"}, nil
	} else {
		//return user{}, fmt.Errorf("Could not find user")
		return user{}, sql.ErrNoRows
	}
}

func TestMain(m *testing.M) {
	r := mux.NewRouter()

	l := logrus.New()
	l.Out = ioutil.Discard

	// This is probably insecure, but that is acceptable for the sake of tests.
	k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatalf("Error generating key. Err: %v", err)
	}

	s = server{router: r, log: l, store: testStore{}, privKey: k}

	os.Exit(m.Run())
}

// test /

func TestRootHandler(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.Handler(s.rootHandler())

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := `{"ping":"pong"}`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body. got: %q want: %q", rr.Body.String(), expected)
	}
}

// test /login

func TestLoginHandler(t *testing.T) {
	req, err := http.NewRequest("POST", "/login", strings.NewReader(`{"password":"test","username":"jordan"}`))
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.Handler(s.loginHandler())

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	resp := make(map[string]interface{})
	json.Unmarshal([]byte(rr.Body.String()), &resp)

	if resp["username"] != "jordan" {
		t.Errorf("handler returned unexpected username. got: %q want: %q", "jordan", resp["username"])
	}

	access_token, err := VerifyJwt(resp["access_token"].(string), s.privKey.Public())
	if err != nil {
		t.Errorf("handler returned an invalid access token. token: %s", access_token)
	}
	refresh_token, err := VerifyJwt(resp["refresh_token"].(string), s.privKey.Public())
	if err != nil {
		t.Errorf("handler returned an invalid refresh token. token: %s", refresh_token)
	}

}
func TestLoginHandlerBadLogin(t *testing.T) {
	var badLoginTests = []struct {
		name     string
		in       string
		expected string
	}{
		{"Bad password test", `{"password": "badpass","username":"jordan"}`, `{"error":"failed to authenticate"}`},
		{"Bad user test", `{"password": "badpass","username":"j"}`, `{"error":"could not find user"}`},
	}
	for _, tc := range badLoginTests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", "/login", strings.NewReader(tc.in))
			if err != nil {
				t.Fatal(err)
			}

			// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
			rr := httptest.NewRecorder()
			handler := http.Handler(s.loginHandler())

			// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
			// directly and pass in our Request and ResponseRecorder.
			handler.ServeHTTP(rr, req)

			// Check the status code is what we expect.
			if status := rr.Code; status != http.StatusUnauthorized {
				t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
			}

			if rr.Body.String() != tc.expected {
				t.Errorf("handler returned unexpected body. got: %q want: %q", rr.Body.String(), tc.expected)
			}
		})
	}

}

// test /test

func TestAuthMw(t *testing.T) {
	loginReq, err := http.NewRequest("POST", "/login", strings.NewReader(`{"username":"jordan","password":"test"}`))
	if err != nil {
		t.Fatal(err)
	}

	lrr := httptest.NewRecorder()
	loginHandler := http.Handler(s.loginHandler())
	loginHandler.ServeHTTP(lrr, loginReq)
	resp := make(map[string]interface{})
	json.Unmarshal([]byte(lrr.Body.String()), &resp)

	access_token := resp["access_token"]

	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.Handler(s.AuthnMw(s.rootHandler()))

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	req.Header = map[string][]string{
		"Authorization": {fmt.Sprintf("Bearer %s", access_token)},
	}
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := `{"ping":"pong"}`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body. got: %q want: %q", rr.Body.String(), expected)
	}

}

// test /refresh
func TestRefresh(t *testing.T) {
	loginReq, err := http.NewRequest("POST", "/login", strings.NewReader(`{"username":"jordan","password":"test"}`))
	if err != nil {
		t.Fatal(err)
	}

	lrr := httptest.NewRecorder()
	loginHandler := http.Handler(s.loginHandler())
	loginHandler.ServeHTTP(lrr, loginReq)
	resp := make(map[string]interface{})
	json.Unmarshal([]byte(lrr.Body.String()), &resp)

	refresh_token := resp["refresh_token"]

	req, err := http.NewRequest("GET", "/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.Handler(s.refreshHandler())

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	req.Header = map[string][]string{
		"Authorization": {fmt.Sprintf("Bearer %s", refresh_token)},
	}
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response body is what we expect.
	access_token, err := VerifyJwt(resp["access_token"].(string), s.privKey.Public())
	if err != nil {
		t.Errorf("handler returned an invalid access token. token: %s", access_token)
	}

}
