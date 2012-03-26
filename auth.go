package http_auth_digest

import "http"

/* 
 Request handlers must take AuthenticatedRequest instead of http.Request
*/
type AuthenticatedRequest struct {
	http.Request
	/* 
	 Authenticated user name. Current API implies that Username is
	 never empty, which means that authentication is always done
	 before calling the request handler.
	*/
	Username string
}

/*
 AuthenticatedHandlerFunc is like http.HandlerFunc, but takes
 AuthenticatedRequest instead of http.Request
*/
type AuthenticatedHandlerFunc func(http.ResponseWriter, *AuthenticatedRequest)

/*
 Authenticator wraps an AuthenticatedHandlerFunc with
 authentication-checking code.

 Typical Authenticator usage is something like:

   authenticator := SomeAuthenticator(...)
   http.HandleFunc("/", authenticator(my_handler))

 Authenticator wrapper checks the user authentication and calls the
 wrapped function only after authentication has succeeded. Otherwise,
 it returns a handler which initiates the authentication procedure.
*/
type Authenticator func(AuthenticatedHandlerFunc) http.HandlerFunc
