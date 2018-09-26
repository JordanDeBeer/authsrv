package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	return user{ID: 1, Username: "jordan", Password: "$2y$12$HbdwCNzjxeHijMGzzatkvOmCw9sO1d5iSwDgmGacng9JjZp7R.Dgm"}, nil

}

func TestMain(m *testing.M) {
	r := mux.NewRouter()

	l := logrus.New()
	l.Out = ioutil.Discard

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

	tok, err := VerifyJwt(resp["access_key"].(string), s.privKey.Public())

	if err != nil {
		t.Errorf("handler returned an invalid token. token: %s", tok)
	}

}

// test /test

func TestAuthMwHandler(t *testing.T) {
	loginReq, err := http.NewRequest("POST", "/login", strings.NewReader(`{"username":"jordan","password":"test"}`))
	if err != nil {
		t.Fatal(err)
	}

	lrr := httptest.NewRecorder()
	loginHandler := http.Handler(s.loginHandler())
	loginHandler.ServeHTTP(lrr, loginReq)
	resp := make(map[string]interface{})
	json.Unmarshal([]byte(lrr.Body.String()), &resp)

	jwt := resp["access_key"]

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
		"Authorization": {fmt.Sprintf("Bearer %s", jwt)},
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
