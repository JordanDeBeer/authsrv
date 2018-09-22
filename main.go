package main

import (
	"authsrv/auth"
	"log"
	"net/http"
	"os"

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
	db := initDb()
	defer db.Close()

	logger := initLogger()

	k, err := initKeys()
	if err != nil {
		log.Fatal("Could not get private key")
	}

	r := http.NewServeMux()

	app := auth.New(r, db, logger, k)
	log.Fatal(http.ListenAndServe(":8080", app.ApplyMw(r)))
}
