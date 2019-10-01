package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func registerHandlers() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/info", serviceInfoHandler)
	http.HandleFunc("/cert/intermediate", intermediateCertHandler)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("Defaulting to port %s", port)
	}

	server := http.Server{
		Addr: fmt.Sprintf(":%s", port),
	}

	registerHandlers()

	log.Printf("Listening on port %s", port)
	log.Fatal(server.ListenAndServe())
}
