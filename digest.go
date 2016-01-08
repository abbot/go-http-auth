package auth

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/context"
)

const DefaultNcCacheSize = 65536

type digest_client struct {
	/*
	   ncs_seen is a bitset used to record the nc values we've seen for a given nonce.
	   This allows us to identify and deny replay attacks without relying on nc values
	   always increasing. That's important since in practice a client's use of multiple
	   server connections, a hierarchy of proxies, and AJAX can cause nc values to arrive
	   out of order (See https://github.com/abbot/go-http-auth/issues/21)
	*/
	ncs_seen  *BitSet
	last_seen int64
}

type DigestAuth struct {
	IsProxy          bool
	Realm            string
	Opaque           string
	Secrets          SecretProvider
	PlainTextSecrets bool
	NcCacheSize      uint64 // The max number of nc values we remember before issuing a new nonce

	/*
	   Approximate size of Client's Cache. When actual number of
	   tracked client nonces exceeds
	   ClientCacheSize+ClientCacheTolerance, ClientCacheTolerance*2
	   older entries are purged.
	*/
	ClientCacheSize      int
	ClientCacheTolerance int

	clients map[string]*digest_client
	mutex   sync.Mutex
}

// check that DigestAuth implements AuthenticatorInterface
var _ = (AuthenticatorInterface)((*DigestAuth)(nil))

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
func (a *DigestAuth) RequireAuth(w http.ResponseWriter, r *http.Request, stale bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if len(a.clients) > a.ClientCacheSize+a.ClientCacheTolerance {
		a.Purge(a.ClientCacheTolerance * 2)
	}
	nonce := RandomKey()
	a.clients[nonce] = &digest_client{ncs_seen: NewBitSet(a.NcCacheSize),
		last_seen: time.Now().UnixNano()}
	value := fmt.Sprintf(`Digest realm="%s", nonce="%s", opaque="%s", algorithm="MD5", qop="auth"`, a.Realm, nonce, a.Opaque)
	if stale {
		value += ", stale=true"
	}
	w.Header().Set(AuthenticateHeaderName(a.IsProxy), value)
	http.Error(w, UnauthorizedStatusText(a.IsProxy), UnauthorizedStatusCode(a.IsProxy))
}

/*
 Parse Authorization header from the http.Request. Returns a map of
 auth parameters or nil if the header is not a valid parsable Digest
 auth header.
*/
func (a *DigestAuth) DigestAuthParams(r *http.Request) map[string]string {
	s := strings.SplitN(r.Header.Get(AuthorizationHeaderName(a.IsProxy)), " ", 2)
	if len(s) != 2 || s[0] != "Digest" {
		return nil
	}

	return ParsePairs(s[1])
}

/*
 Check if request contains valid authentication data. Returns a triplet
 of username, authinfo, stale where username is the name of the authenticated
 user or an empty string, authinfo is the contents for the optional Authentication-Info
 response header, and stale indicates whether the server-returned Authenticate header
 should specify stale=true (see https://www.ietf.org/rfc/rfc2617.txt Section 3.3)
*/
func (da *DigestAuth) CheckAuth(r *http.Request) (username string, authinfo *string, stale bool) {
	da.mutex.Lock()
	defer da.mutex.Unlock()
	username = ""
	authinfo = nil
	stale = false
	auth := da.DigestAuthParams(r)
	if auth == nil || da.Opaque != auth["opaque"] || auth["algorithm"] != "MD5" || auth["qop"] != "auth" {
		return
	}

	/* Check whether the requested URI matches auth header
	   NOTE: when we're a proxy and method is CONNECT, the request and auth uri
	   specify a hostname not a path, e.g.

	   CONNECT 1-edge-chat.facebook.com:443 HTTP/1.1
	   User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0
	   Proxy-Connection: keep-alive
	   Connection: keep-alive
	   Host: 1-edge-chat.facebook.com:443
	   Proxy-Authorization: Digest username="test", realm="",
	         nonce="iQSz9RcA1Qsa6ono",
	         uri="1-edge-chat.facebook.com:443",
	         algorithm=MD5,
	         response="a077a4676d60ff8bf48577ad7c7360d6",
	         opaque="EN3BwDsuWB5F6IWR", qop=auth, nc=0000000c,
	         cnonce="548d04d1bbd63926"
	*/

	if r.Method == "CONNECT" {
		if r.RequestURI != auth["uri"] {
			return
		}
	} else {

		// Check if the requested URI matches auth header
		switch u, err := url.Parse(auth["uri"]); {
		case err != nil:
			return
		case r.URL == nil:
			return
		case len(u.Path) > len(r.URL.Path):
			return
		case !strings.HasPrefix(r.URL.Path, u.Path):
			return
		}
	}

	HA1 := da.Secrets(auth["username"], da.Realm)
	if da.PlainTextSecrets {
		HA1 = H(auth["username"] + ":" + da.Realm + ":" + HA1)
	}
	HA2 := H(r.Method + ":" + auth["uri"])
	KD := H(strings.Join([]string{HA1, auth["nonce"], auth["nc"], auth["cnonce"], auth["qop"], HA2}, ":"))

	if subtle.ConstantTimeCompare([]byte(KD), []byte(auth["response"])) != 1 {
		return
	}

	// At this point crypto checks are completed and validated.
	// Now check if the session is valid.

	nc, err := strconv.ParseUint(auth["nc"], 16, 64)
	if err != nil {
		return
	}

	client, ok := da.clients[auth["nonce"]]
	if !ok {
		stale = true
		return
	}

	// Check the nonce-count
	if nc >= client.ncs_seen.Size() {
		// nc exceeds the size of our bitset. We can just treat this the
		// same as a stale nonce
		stale = true
		return
	} else if client.ncs_seen.Get(nc) {
		// We've already seen this nc! Possible replay attack!
		return
	}
	client.ncs_seen.Set(nc)
	client.last_seen = time.Now().UnixNano()

	resp_HA2 := H(":" + auth["uri"])
	rspauth := H(strings.Join([]string{HA1, auth["nonce"], auth["nc"], auth["cnonce"], auth["qop"], resp_HA2}, ":"))

	info := fmt.Sprintf(`qop="auth", rspauth="%s", cnonce="%s", nc="%s"`, rspauth, auth["cnonce"], auth["nc"])
	return auth["username"], &info, stale
}

/*
 Default values for ClientCacheSize and ClientCacheTolerance for DigestAuth
*/
const DefaultClientCacheSize = 1000
const DefaultClientCacheTolerance = 100

/*
 Wrap returns an Authenticator which uses HTTP Digest
 authentication. Arguments:

 realm: The authentication realm.

 secrets: SecretProvider which must return HA1 digests for the same
 realm as above.
*/
func (a *DigestAuth) Wrap(wrapped AuthenticatedHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if username, authinfo, stale := a.CheckAuth(r); username == "" {
			a.RequireAuth(w, r, stale)
		} else {
			ar := &AuthenticatedRequest{Request: *r, Username: username}
			if authinfo != nil {
				w.Header().Set(AuthenticationInfoHeaderName(a.IsProxy), *authinfo)
			}
			wrapped(w, ar)
		}
	}
}

/*
 JustCheck returns function which converts an http.HandlerFunc into a
 http.HandlerFunc which requires authentication. Username is passed as
 an extra X-Authenticated-Username header.
*/
func (a *DigestAuth) JustCheck(wrapped http.HandlerFunc) http.HandlerFunc {
	return a.Wrap(func(w http.ResponseWriter, ar *AuthenticatedRequest) {
		ar.Header.Set("X-Authenticated-Username", ar.Username)
		wrapped(w, &ar.Request)
	})
}

// NewContext returns a context carrying authentication information for the request.
func (a *DigestAuth) NewContext(ctx context.Context, r *http.Request) context.Context {
	username, authinfo, stale := a.CheckAuth(r)
	info := &Info{Username: username, ResponseHeaders: make(http.Header)}
	if username != "" {
		info.Authenticated = true
		info.ResponseHeaders.Set(AuthenticationInfoHeaderName(a.IsProxy), *authinfo)
	} else {
		// return back digest XYZ-Authenticate header
		if len(a.clients) > a.ClientCacheSize+a.ClientCacheTolerance {
			a.Purge(a.ClientCacheTolerance * 2)
		}
		nonce := RandomKey()
		a.clients[nonce] = &digest_client{ncs_seen: NewBitSet(a.NcCacheSize),
			last_seen: time.Now().UnixNano()}
		value := fmt.Sprintf(`Digest realm="%s", nonce="%s", opaque="%s", algorithm="MD5", qop="auth"`,
			a.Realm, nonce, a.Opaque)
		if stale {
			value += ", stale=true"
		}
		info.ResponseHeaders.Set(AuthenticateHeaderName(a.IsProxy), value)
	}
	return context.WithValue(ctx, infoKey, info)
}

func NewDigestAuthenticator(realm string, secrets SecretProvider) *DigestAuth {
	da := &DigestAuth{
		Opaque:               RandomKey(),
		Realm:                realm,
		Secrets:              secrets,
		PlainTextSecrets:     false,
		NcCacheSize:          DefaultNcCacheSize,
		ClientCacheSize:      DefaultClientCacheSize,
		ClientCacheTolerance: DefaultClientCacheTolerance,
		clients:              map[string]*digest_client{}}
	return da
}

func NewDigestAuthenticatorForProxy(realm string, secrets SecretProvider) *DigestAuth {
	da := NewDigestAuthenticator(realm, secrets)
	da.IsProxy = true
	return da
}
