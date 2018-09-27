package main

import (
	"authsrv/auth"
	"crypto/ecdsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/sirupsen/logrus"
)

func initUserStore() auth.UserStore {
	dbinfo := fmt.Sprintf("host=%s user=%s password=%s sslmode=disable", dbHost, dbUser, dbPass)
	db, err := sql.Open("postgres", dbinfo)
	if err != nil {
		log.Fatalf("Error in initDb(). No database connection. Error: %v", err)
	}
	s := auth.NewPsqlUserStore(db)
	return s
}

func initLogger() *logrus.Logger {
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = logrus.InfoLevel.String()
	}
	lvl, err := logrus.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("Could not set log level. Error: %v", err)
	}
	logger := &logrus.Logger{
		Out:       os.Stdout,
		Formatter: new(logrus.JSONFormatter),
		Hooks:     make(logrus.LevelHooks),
		Level:     lvl,
	}
	return logger
}

func initKeys() (*ecdsa.PrivateKey, error) {
	data, err := ioutil.ReadFile("/app/keys/private")
	if err != nil {
		return nil, fmt.Errorf("Error reading keyfile. Error: %v", err)
	}
	block, _ := pem.Decode(data)

	if block == nil {
		return nil, fmt.Errorf("Error loading key. Error: %v", err)
	}

	if block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("Wrong type of key - %s", block.Type)
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Error parsing key. Error: %v", err)
	}
	return privateKey, nil
}
