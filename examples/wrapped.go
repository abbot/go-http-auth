// +build ignore

/*
 Example demonstrating how to wrap an application which is unaware of
 authenticated requests with a "pass-through" authentication

 Build with:

 go build wrapped.go
*/

package main

import (
	"fmt"
	"net/http"

	auth ".."
)

func secret(user, realm string) string {
	if user == "john" {
		// password is "hello"
		return "$1$dlPL2MqE$oQmn16q49SqdmhenQuNgs1"
	}
	return ""
}

func regularHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<html><body><h1>This application is unaware of authentication</h1></body></html>")
}

func main() {
	authenticator := auth.NewBasicAuthenticator("example.com", secret)
	http.HandleFunc("/", auth.JustCheck(authenticator, regularHandler))
	http.ListenAndServe(":8080", nil)
}
