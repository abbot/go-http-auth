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

const DigestAlgorithm = "MD5"
const DigestQop = "auth"

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
	value := fmt.Sprintf(`Digest realm="%s", nonce="%s", opaque="%s", algorithm="%s", qop="%s"`, a.Realm, nonce,
		a.Opaque, DigestAlgorithm, DigestQop)
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

type DigestAuthResult struct {
	Username string
	Authinfo string
}

var ErrDigestAuthMissing = fmt.Errorf("missing digest auth header")
var ErrDigestOpaqueMismatch = fmt.Errorf("client opaque does not match server opaque")
var ErrDigestAlgorithmMismatch = fmt.Errorf("algorithm mismatch; expected %s", DigestAlgorithm)
var ErrDigestQopMismatch = fmt.Errorf("qop mismatch; expected %s", DigestQop)
var ErrDigestResponseMismatch = fmt.Errorf("response mismatch")
var ErrDigestRepeatedNc = fmt.Errorf("repeated nc! (replay attack?)")
var ErrDigestStaleNonce = fmt.Errorf("stale nonce")

type ErrDigestUriMismatch struct {
	fromRequest string
	fromAuth    string
}

func (e ErrDigestUriMismatch) Error() string {
	return fmt.Sprintf("path mismatch: %s != %s", e.fromRequest, e.fromAuth)
}

type ErrDigestHostMismatch struct {
	fromRequest string
	fromAuth    string
}

func (e ErrDigestHostMismatch) Error() string {
	return fmt.Sprintf("host mismatch: %s != %s", e.fromRequest, e.fromAuth)
}

type ErrDigestBadNc struct {
	err error
}

func (e ErrDigestBadNc) Error() string {
	return fmt.Sprintf("failed to parse nc: %s", e.err)
}

type ErrDigestBadUri struct {
	uri string
}

func (e ErrDigestBadUri) Error() string {
	return fmt.Sprintf("failed to parse uri: %s", e.uri)
}

/*
 CheckAuth checks whether the request contains valid authentication data. Returns
 a tuple of DigestAuthResult, error. On success, err is nil and the result contains
 the name of the authenticated user and authinfo for the contents of the optional
 XYZ-Authentication-Info response header. If err==ErrDigestStaleNonce then the caller
 should specify stale=true (see https://www.ietf.org/rfc/rfc2617.txt Section 3.3) when
 sending the XYZ-Authenticate header.
*/
func (da *DigestAuth) CheckAuth(r *http.Request) (*DigestAuthResult, error) {
	da.mutex.Lock()
	defer da.mutex.Unlock()
	result := &DigestAuthResult{}
	auth := da.DigestAuthParams(r)
	if auth == nil {
		return nil, ErrDigestAuthMissing
	} else if da.Opaque != auth["opaque"] {
		return nil, ErrDigestOpaqueMismatch
	} else if auth["algorithm"] != DigestAlgorithm {
		return nil, ErrDigestAlgorithmMismatch
	} else if auth["qop"] != DigestQop {
		return nil, ErrDigestQopMismatch
	}

	// Checking the proxy auth uri is surprisingly difficult...
	//
	// Typical examples: note that querystring is included in Proxy-Authorization uri so we
	// must strip it off before comparing to our request path
	//
	// GET http://start.ubuntu.com/14.04/Google/?sourceid=hp HTTP/1.1
	// User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0
	// Host: start.ubuntu.com
	// Proxy-Authorization: Digest username="test", realm="Proxy", nonce="FhnRLUZSHgPUhw5S", uri="/14.04/Google/?sourceid=hp",
	// algorithm=MD5, response="c9f50ab9dd1b1a67c8ca03d1e1c4668a", opaque="6d33bebd35010c78c846cec1ed34373d", qop=auth, nc=00000001, cnonce="87e41ec0b553d1e3"
	//
	// For connect, there is no path so we compare hostname and port
	//
	// CONNECT 2.rto.microsoft.com:443 HTTP/1.1
	// Host: 2.rto.microsoft.com:443
	// User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0
	// Proxy-Authorization: Digest username="test", realm="Proxy", nonce="69uac299Qm9CdrHd", uri="2.rto.microsoft.com:443",
	// algorithm=MD5, response="30d5eb727a1aaea879599d813bcaef57", opaque="6d33bebd35010c78c846cec1ed34373d", qop=auth, nc=00000001, cnonce="3057a2b17430ba89"
	//
	// Except that sometimes the ports don't match, so we have to exclude them from the matching logic...
	//
	// CONNECT core25usw2.fabrik.nytimes.com.:80 HTTP/1.1
	// User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0
	// Host: core25usw2.fabrik.nytimes.com.:80
	// Proxy-Authorization: Digest username="test", realm="Proxy", nonce="r+10+JoybdZlWpaW", uri="core25usw2.fabrik.nytimes.com.:443",
	// algorithm=MD5, response="a827b29b872613509052ff8b68e3b365", opaque="6d33bebd35010c78c846cec1ed34373d", qop=auth, nc=00000001, cnonce="70876e4bbcdb1e4a"
	//
	// Or clients send malformed data (like the extra slashes here). It's not clear whether the client is sending malformed data, or whether they
	// are trying to use protocol-relative addressing and the golang url parser just can't handle it.
	// The request line path is parsed as "//www/delivery/retarget.php"" but the proxy auth uri path is parsed as "/delivery/retarget.php"
	//
	// GET http://ap.lijit.com//www/delivery/retarget.php?a=a&r=rtb_criteo&pid=9&3pid=1bbc9197-bea9-4fad-892a-f9ac383cbccd&cb=e1791e3c-eb07-4396-91e1-7bcfce7d3e17 HTTP/1.1
	// Host: ap.lijit.com
	// User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0^M
	// Proxy-Authorization: Digest username="test", realm="Proxy", nonce="fRFG/XucPibCZ+wy", uri="//www/delivery/retarget.php?a=a&r=rtb_criteo&pid=9&3pid=1bbc9197-bea9-4fad-892a-f9ac383cbccd&cb=e1791e3c-eb07-4396-91e1-7bcfce7d3e17",
	//        algorithm=MD5, response="58c7c6b5b8419f9a87d5e81e87ef2027", opaque="6d33bebd35010c78c846cec1ed34373d", qop=auth, nc=00000001, cnonce="620ce89123d29c75"^M
	//
	// Another example. The request line path is parsed as "//dynamic_preroll_playlist.fmil" and the proxy auth uri path is parsed as "" (seen on independent.co.uk)
	//
	// POST http://plg2.yumenetworks.com//dynamic_preroll_playlist.fmil?domain=2158REpjOITz&yvbsv=6.2.9.3&&protocol_version=2.0&sdk_ver=3.1.9.20&width=300&height=250&embeddedIn=http%3A%2F%2Fwww.independent.co.uk%2Fnews%2Fworld%2Famericas&
	//    sdk_url=http%3A%2F%2Fplg1.yumenetworks.com%2Fyvp%2F20%2Fvpaid%2Fcr%2F&viewport=970,1219,0,0,300,250,970,1447&ytp=0,228,1301,673,970,1447,1301,6843&ypt=none& HTTP/1.1^M
	// Host: plg2.yumenetworks.com^M
	// Proxy-Authorization: Digest username="magnus", realm="Magthor Proxy", nonce="yV12jLlyzAb7Lo9R", uri="//dynamic_preroll_playlist.fmil?domain=2158REpjOITz&yvbsv=6.2.9.3&&protocol_version=2.0&sdk_ver=3.1.9.20&width=300&height=250&
	//     embeddedIn=http%3A%2F%2Fwww.independent.co.uk%2Fnews%2Fworld%2Famericas&sdk_url=http%3A%2F%2Fplg1.yumenetworks.com%2Fyvp%2F20%2Fvpaid%2Fcr%2F&viewport=970,1219,0,0,300,250,970,1447&ytp=0,228,1301,673,970,1447,1301,6843&ypt=none&", algorithm=MD5,
	//    response="0813fb545b1558bef224b4ecdedf0e2f", opaque="6d33bebd35010c78c846cec1ed34373d", qop=auth, nc=00000279, cnonce="e59ed7e19d323c8b"^M
	//

	// We have to parse auth["uri"] instead of comparing directly since it could contain url-escaped chars
	authPath, err := url.Parse(auth["uri"])
	if err != nil {
		return nil, &ErrDigestBadUri{auth["uri"]}
	}

	if r.URL.Path == "" {
		// e.g. CONNECT
		// compare without port numbers, if any
		if strings.Split(r.RequestURI, ":")[0] != strings.Split(auth["uri"], ":")[0] {
			return nil, &ErrDigestHostMismatch{r.RequestURI, auth["uri"]}
		}
	} else {
		// e.g. GET
		if authPath.Path == "" {
			// e.g. path like "//dynamic_preroll_playlist.fmil?..." which isn't parsed correctly
			compare := strings.Split(auth["uri"], "?")[0]
			if r.URL.Path != compare {
				return nil, &ErrDigestUriMismatch{r.URL.Path, compare + " (?)"}
			}
		} else if r.URL.Path != authPath.Path {
			return nil, &ErrDigestUriMismatch{r.URL.Path, authPath.Path}
		}
		//if !strings.HasPrefix(authPath.Path, r.URL.Path) {
		//	return nil, &ErrDigestUriMismatch{r.URL.Path, authPath.Path}
		//}
	}

	HA1 := da.Secrets(auth["username"], da.Realm)
	if da.PlainTextSecrets {
		HA1 = H(auth["username"] + ":" + da.Realm + ":" + HA1)
	}
	HA2 := H(r.Method + ":" + auth["uri"])

	// NOTE: it could be that the client nonce doesn't match ours (we check that later), but this calc
	// verifies they provided the correct user password
	KD := H(strings.Join([]string{HA1, auth["nonce"], auth["nc"], auth["cnonce"], auth["qop"], HA2}, ":"))

	if subtle.ConstantTimeCompare([]byte(KD), []byte(auth["response"])) != 1 {
		return nil, ErrDigestResponseMismatch
	}

	// At this point crypto checks are completed and validated.
	// Now check if the session is valid.
	nc, err := strconv.ParseUint(auth["nc"], 16, 64)
	if err != nil {
		return nil, &ErrDigestBadNc{err}
	}

	client, ok := da.clients[auth["nonce"]]
	if !ok {
		return nil, ErrDigestStaleNonce
	}

	// Check the nonce-count
	if nc >= client.ncs_seen.Size() {
		// nc exceeds the size of our bitset. We can just treat this the
		// same as a stale nonce
		return nil, ErrDigestStaleNonce
	} else if client.ncs_seen.Get(nc) {
		// We've already seen this nc! Possible replay attack!
		return nil, ErrDigestRepeatedNc
	}

	// NOTE: we don't register that we've seen this nc until this point; not sure if that is correct. It may
	// be preferable to parse nonce and nc as one of the first operations so that we get nc stored in our bitmap
	// regardless of whether or not the request successfully passes authorization
	client.ncs_seen.Set(nc)
	client.last_seen = time.Now().UnixNano()

	resp_HA2 := H(":" + auth["uri"])
	rspauth := H(strings.Join([]string{HA1, auth["nonce"], auth["nc"], auth["cnonce"], auth["qop"], resp_HA2}, ":"))
	result.Authinfo = fmt.Sprintf(`qop="%s", rspauth="%s", cnonce="%s", nc="%s"`, DigestQop, rspauth, auth["cnonce"], auth["nc"])
	result.Username = auth["username"]
	return result, nil
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
		if result, err := a.CheckAuth(r); err != nil {
			a.RequireAuth(w, r, err == ErrDigestStaleNonce)
		} else {
			ar := &AuthenticatedRequest{Request: *r, Username: result.Username}
			w.Header().Set(AuthenticationInfoHeaderName(a.IsProxy), result.Authinfo)
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
	result, err := a.CheckAuth(r)
	info := &Info{Username: result.Username, ResponseHeaders: make(http.Header)}
	if err == nil {
		info.Authenticated = true
		info.ResponseHeaders.Set(AuthenticationInfoHeaderName(a.IsProxy), result.Authinfo)
	} else {
		// return back digest XYZ-Authenticate header
		if len(a.clients) > a.ClientCacheSize+a.ClientCacheTolerance {
			a.Purge(a.ClientCacheTolerance * 2)
		}
		nonce := RandomKey()
		a.clients[nonce] = &digest_client{ncs_seen: NewBitSet(a.NcCacheSize),
			last_seen: time.Now().UnixNano()}
		value := fmt.Sprintf(`Digest realm="%s", nonce="%s", opaque="%s", algorithm="%s", qop="%s"`,
			a.Realm, nonce, a.Opaque, DigestAlgorithm, DigestQop)
		if err == ErrDigestStaleNonce {
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
