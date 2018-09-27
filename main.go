package main

import (
	"authsrv/auth"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

// configuration data
var (
	// postgres
	dbHost = os.Getenv("DB_HOST")
	dbUser = os.Getenv("DB_USER")
	dbPass = os.Getenv("DB_PASS")
)

func main() {
	s := initUserStore()

	l := initLogger()

	k, err := initKeys()
	if err != nil {
		log.Fatalf("Could not get private key. Error: %v", err)
	}

	r := mux.NewRouter()

	auth.New(r, s, l, k)
	log.Fatal(http.ListenAndServe(":8080", (r)))
}
