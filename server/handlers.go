package main

import (
	"net/http"
)

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome. Please use the SSH client to use this service"))
}
