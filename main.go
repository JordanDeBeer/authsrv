package main

import (
	"authsrv/auth"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

// configuration data
var (
	version string

	// postgres
	dbHost = os.Getenv("DB_HOST")
	dbUser = os.Getenv("DB_USER")
	dbPass = os.Getenv("DB_PASS")
)

func main() {
	time.Sleep(2 * time.Second)
	fmt.Println("Starting authsrv version", version)
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
