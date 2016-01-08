package auth

import (
	"bufio"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuthDigest(t *testing.T) {

	for _, isProxy := range []bool{false, true} {
		secrets := HtdigestFileProvider("test.htdigest")
		da := &DigestAuth{IsProxy: isProxy,
			Opaque:      "U7H+ier3Ae8Skd/g",
			Realm:       "example.com",
			Secrets:     secrets,
			NcCacheSize: 20,
			clients:     map[string]*digest_client{}}
		r := &http.Request{}
		r.Method = "GET"
		if u, _, _ := da.CheckAuth(r); u != "" {
			t.Fatal("non-empty auth for empty request header")
		}
		r.Header = http.Header(make(map[string][]string))
		r.Header.Set(AuthorizationHeaderName(da.IsProxy), "Digest blabla")
		if u, _, _ := da.CheckAuth(r); u != "" {
			t.Fatal("non-empty auth for bad request header")
		}

		r.URL, _ = url.Parse("/t2")
		r.Header.Set(AuthorizationHeaderName(da.IsProxy), `Digest username="test", realm="example.com", nonce="Vb9BP/h81n3GpTTB", uri="/t2", cnonce="NjE4MTM2", nc=00000001, qop="auth", response="ffc357c4eba74773c8687e0bc724c9a3", opaque="U7H+ier3Ae8Skd/g", algorithm="MD5"`)
		u, _, stale := da.CheckAuth(r)
		if u != "" {
			t.Fatal("non-empty auth for unknown client")
		}
		if !stale {
			t.Fatal("stale should be true")
		}

		da.clients["Vb9BP/h81n3GpTTB"] = &digest_client{ncs_seen: NewBitSet(da.NcCacheSize),
			last_seen: time.Now().UnixNano()}
		u, _, stale = da.CheckAuth(r)
		if u != "test" {
			t.Fatal("empty auth for legitimate client")
		}
		if stale {
			t.Fatal("stale should be false")
		}

		r.URL, _ = url.Parse("/")
		da.clients["Vb9BP/h81n3GpTTB"] = &digest_client{ncs_seen: NewBitSet(da.NcCacheSize), last_seen: time.Now().UnixNano()}
		if u, _, _ := da.CheckAuth(r); u != "" {
			t.Fatal("non-empty auth for bad request path")
		}

		r.URL, _ = url.Parse("/t3")
		da.clients["Vb9BP/h81n3GpTTB"] = &digest_client{ncs_seen: NewBitSet(da.NcCacheSize), last_seen: time.Now().UnixNano()}
		if u, _, _ := da.CheckAuth(r); u != "" {
			t.Fatal("non-empty auth for bad request path")
		}

		da.clients["+RbVXSbIoa1SaJk1"] = &digest_client{ncs_seen: NewBitSet(da.NcCacheSize), last_seen: time.Now().UnixNano()}
		r.Header.Set(AuthorizationHeaderName(da.IsProxy), `Digest username="test", realm="example.com", nonce="+RbVXSbIoa1SaJk1", uri="/", cnonce="NjE4NDkw", nc=00000001, qop="auth", response="c08918024d7faaabd5424654c4e3ad1c", opaque="U7H+ier3Ae8Skd/g", algorithm="MD5"`)
		if u, _, _ := da.CheckAuth(r); u != "test" {
			t.Fatal("empty auth for valid request in subpath")
		}

		// nc checking, we've already seen 00000001 so this should fail
		if u, _, _ := da.CheckAuth(r); u != "" {
			t.Fatal("non-empty auth for already-seen nc")
		}

		// an updated request with nc 00000005 should succeed
		r.Header.Set(AuthorizationHeaderName(da.IsProxy), `Digest username="test", realm="example.com", nonce="+RbVXSbIoa1SaJk1", uri="/", cnonce="NjE4NDkw", nc=00000005, qop="auth", response="c553c9a48ec99de9474e662934f73de2", opaque="U7H+ier3Ae8Skd/g", algorithm="MD5"`)
		if u, _, _ := da.CheckAuth(r); u != "test" {
			t.Fatal("empty auth for valid nc 00000005")
		}

		// but repeating it should fail...
		r.Header.Set(AuthorizationHeaderName(da.IsProxy), `Digest username="test", realm="example.com", nonce="+RbVXSbIoa1SaJk1", uri="/", cnonce="NjE4NDkw", nc=00000005, qop="auth", response="c553c9a48ec99de9474e662934f73de2", opaque="U7H+ier3Ae8Skd/g", algorithm="MD5"`)
		if u, _, _ := da.CheckAuth(r); u != "" {
			t.Fatal("non-empty auth for repeated nc 00000005")
		}

		// an updated request with nc 00000002 should succeed even though it's out of order, since it hasn't been seen yet
		r.Header.Set(AuthorizationHeaderName(da.IsProxy), `Digest username="test", realm="example.com", nonce="+RbVXSbIoa1SaJk1", uri="/", cnonce="NjE4NDkw", nc=00000002, qop="auth", response="1c2a64978d9e8a61f823240304b95afd", opaque="U7H+ier3Ae8Skd/g", algorithm="MD5"`)
		if u, _, _ := da.CheckAuth(r); u != "test" {
			t.Fatal("empty auth for valid nc 00000002")
		}

		if da.clients["+RbVXSbIoa1SaJk1"].ncs_seen.String() != "01100100000000000000" {
			t.Fatal("ncs_seen bitmap didn't match expected")
		}

	}
}

func TestDigestAuthParams(t *testing.T) {
	body := `GET http://fonts.googleapis.com/css?family=Source+Sans+Pro:400,700,400italic,700italic|Source+Code+Pro HTTP/1.1
Host: fonts.googleapis.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0
Accept: text/css,/;q=0.1
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://elm-lang.org/assets/style.css
Authorization: Digest username="test", realm="", nonce="FRPnGdb8lvM1UHhi", uri="/css?family=Source+Sans+Pro:400,700,400italic,700italic|Source+Code+Pro", algorithm=MD5, response="fdcdd78e5b306ffed343d0ec3967f2e5", opaque="lEgVjogmIar2fg/t", qop=auth, nc=00000001, cnonce="e76b05db27a3b323"
Connection: keep-alive

`
	da := &DigestAuth{}
	req, _ := http.ReadRequest(bufio.NewReader(strings.NewReader(body)))
	params := da.DigestAuthParams(req)
	if params["uri"] != "/css?family=Source+Sans+Pro:400,700,400italic,700italic|Source+Code+Pro" {
		t.Fatal("failed to parse uri with embedded commas")
	}

}
