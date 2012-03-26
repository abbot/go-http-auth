package auth

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type digest_client struct {
	nc        uint64
	last_seen int64
}

type DigestAuth struct {
	Realm   string
	Opaque  string
	Secrets SecretProvider

	/* 
	 Approximate size of Client's Cache. When actual number of
	 tracked client nonces exceeds
	 ClientCacheSize+ClientCacheTolerance, ClientCacheTolerance*2
	 older entries are purged.
	*/
	ClientCacheSize      int
	ClientCacheTolerance int

	clients map[string]*digest_client
}

type digest_cache_entry struct {
	nonce     string
	last_seen int64
}

type digest_cache []digest_cache_entry

func (c digest_cache) Less(i, j int) bool {
	return c[i].last_seen < c[j].last_seen
}

func (c digest_cache) Len() int {
	return len(c)
}

func (c digest_cache) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

/*
 Remove count oldest entries from DigestAuth.clients
*/
func (a *DigestAuth) Purge(count int) {
	entries := make([]digest_cache_entry, 0, len(a.clients))
	for nonce, client := range a.clients {
		entries = append(entries, digest_cache_entry{nonce, client.last_seen})
	}
	cache := digest_cache(entries)
	sort.Sort(cache)
	for _, client := range cache[:count] {
		delete(a.clients, client.nonce)
	}
}

/*
 http.Handler for DigestAuth which initiates the authentication process
 (or requires reauthentication).
*/
func (a *DigestAuth) RequireAuth(w http.ResponseWriter, r *http.Request) {
	if len(a.clients) > a.ClientCacheSize+a.ClientCacheTolerance {
		a.Purge(a.ClientCacheTolerance * 2)
	}
	nonce := RandomKey()
	a.clients[nonce] = &digest_client{nc: 0, last_seen: time.Now().UnixNano()}
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Digest realm="%s", nonce="%s", opaque="%s", algorithm="MD5", qop="auth"`,
			a.Realm, nonce, a.Opaque))
	w.WriteHeader(401)
	w.Write([]byte("401 Unauthorized\n"))
}

/*
 Parse Authorization header from the http.Request. Returns a map of
 auth parameters or nil if the header is not a valid parsable Digest
 auth header.
*/
func DigestAuthParams(r *http.Request) map[string]string {
	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 || s[0] != "Digest" {
		return nil
	}

	result := map[string]string{}
	for _, kv := range strings.Split(s[1], ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		result[strings.Trim(parts[0], "\" ")] = strings.Trim(parts[1], "\" ")
	}
	return result
}

/* 
 Check if request contains valid authentication data. Returns a pair
 of username, authinfo where username is the name of the authenticated
 user or an empty string and authinfo is the contents for the optional
 Authentication-Info response header.
*/
func (da *DigestAuth) CheckAuth(r *http.Request) (username string, authinfo *string) {
	username = ""
	authinfo = nil
	auth := DigestAuthParams(r)
	if auth == nil || da.Opaque != auth["opaque"] || auth["algorithm"] != "MD5" || auth["qop"] != "auth" {
		return
	}

	// Check if the requested URI matches auth header
	if r.URL == nil || len(auth["uri"]) > len(r.URL.Path) || r.URL.Path[:len(auth["uri"])] != auth["uri"] {
		return
	}

	HA1 := da.Secrets(auth["username"], da.Realm)
	HA2 := H(r.Method + ":" + auth["uri"])
	KD := H(strings.Join([]string{HA1, auth["nonce"], auth["nc"], auth["cnonce"], auth["qop"], HA2}, ":"))

	if KD != auth["response"] {
		return
	}

	// At this point crypto checks are completed and validated.
	// Now check if the session is valid.

	nc, err := strconv.ParseUint(auth["nc"], 16, 64)
	if err != nil {
		return
	}

	if client, ok := da.clients[auth["nonce"]]; !ok {
		return
	} else {
		if client.nc != 0 && client.nc >= nc {
			return
		}
		client.nc = nc
		client.last_seen = time.Now().UnixNano()
	}

	resp_HA2 := H(":" + auth["uri"])
	rspauth := H(strings.Join([]string{HA1, auth["nonce"], auth["nc"], auth["cnonce"], auth["qop"], resp_HA2}, ":"))

	info := fmt.Sprintf(`qop="auth", rspauth="%s", cnonce="%s", nc="%s"`, rspauth, auth["cnonce"], auth["nc"])
	return auth["username"], &info
}

/*
 Default values for ClientCacheSize and ClientCacheTolerance for DigestAuth
*/
const DefaultClientCacheSize = 1000
const DefaultClientCacheTolerance = 100

/* 
 DigestAuthenticator returns an Authenticator which uses HTTP Digest
 authentication. Arguments:

 realm: The authentication realm.

 secrets: SecretProvider which must return HA1 digests for the same
 realm as above.

 cache: Optional one or two arguments, first is the size of the
 clients cache, second is the tolerance for the cache. Default values
 are used if not given.
*/
func DigestAuthenticator(realm string, secrets SecretProvider, cache ...int) Authenticator {
	da := &DigestAuth{
		Opaque:               RandomKey(),
		Realm:                realm,
		Secrets:              secrets,
		ClientCacheSize:      DefaultClientCacheSize,
		ClientCacheTolerance: DefaultClientCacheTolerance,
		clients:              map[string]*digest_client{}}

	switch {
	case len(cache) > 0:
		da.ClientCacheSize = cache[0]
		fallthrough
	case len(cache) > 1:
		da.ClientCacheTolerance = cache[1]
		fallthrough
	case len(cache) > 2:
		panic("Unknown extra arguments to DigestAuthenticator")
	}

	return func(wrapped AuthenticatedHandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if username, authinfo := da.CheckAuth(r); username == "" {
				da.RequireAuth(w, r)
			} else {
				dr := &AuthenticatedRequest{Request: *r, Username: username}
				if authinfo != nil {
					w.Header().Set("Authentication-Info", *authinfo)
				}
				wrapped(w, dr)
			}
		}
	}
}
