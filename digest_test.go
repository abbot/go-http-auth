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
	secrets := HtdigestFileProvider("test.htdigest")
	da := &DigestAuth{Opaque: "U7H+ier3Ae8Skd/g",
		Realm:   "example.com",
		Secrets: secrets,
		clients: map[string]*digest_client{}}
	r := &http.Request{}
	r.Method = "GET"
	if u, _ := da.CheckAuth(r); u != "" {
		t.Fatal("non-empty auth for empty request header")
	}
	r.Header = http.Header(make(map[string][]string))
	r.Header.Set("Authorization", "Digest blabla")
	if u, _ := da.CheckAuth(r); u != "" {
		t.Fatal("non-empty auth for bad request header")
	}
	r.Header.Set("Authorization", `Digest username="test", realm="example.com", nonce="Vb9BP/h81n3GpTTB", uri="/t2", cnonce="NjE4MTM2", nc=00000001, qop="auth", response="ffc357c4eba74773c8687e0bc724c9a3", opaque="U7H+ier3Ae8Skd/g", algorithm="MD5"`)
	if u, _ := da.CheckAuth(r); u != "" {
		t.Fatal("non-empty auth for unknown client")
	}

	r.URL, _ = url.Parse("/t2")
	da.clients["Vb9BP/h81n3GpTTB"] = &digest_client{nc: 0, last_seen: time.Now().UnixNano()}
	if u, _ := da.CheckAuth(r); u != "test" {
		t.Fatal("empty auth for legitimate client")
	}

	// our nc is now 0, client nc is 1
	if u, _ := da.CheckAuth(r); u != "" {
		t.Fatal("non-empty auth for outdated nc")
	}

	// try again with nc checking off
	da.DisableNonceCountCheck = true
	if u, _ := da.CheckAuth(r); u != "test" {
		t.Fatal("empty auth for outdated nc even though nc checking is off")
	}
	da.DisableNonceCountCheck = false

	r.URL, _ = url.Parse("/")
	da.clients["Vb9BP/h81n3GpTTB"] = &digest_client{nc: 0, last_seen: time.Now().UnixNano()}
	if u, _ := da.CheckAuth(r); u != "" {
		t.Fatal("non-empty auth for bad request path")
	}

	r.URL, _ = url.Parse("/t3")
	da.clients["Vb9BP/h81n3GpTTB"] = &digest_client{nc: 0, last_seen: time.Now().UnixNano()}
	if u, _ := da.CheckAuth(r); u != "" {
		t.Fatal("non-empty auth for bad request path")
	}

	da.clients["+RbVXSbIoa1SaJk1"] = &digest_client{nc: 0, last_seen: time.Now().UnixNano()}
	r.Header.Set("Authorization", `Digest username="test", realm="example.com", nonce="+RbVXSbIoa1SaJk1", uri="/", cnonce="NjE4NDkw", nc=00000001, qop="auth", response="c08918024d7faaabd5424654c4e3ad1c", opaque="U7H+ier3Ae8Skd/g", algorithm="MD5"`)
	if u, _ := da.CheckAuth(r); u != "test" {
		t.Fatal("empty auth for valid request in subpath")
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
	req, _ := http.ReadRequest(bufio.NewReader(strings.NewReader(body)))
	params := DigestAuthParams(req)
	if params["uri"] != "/css?family=Source+Sans+Pro:400,700,400italic,700italic|Source+Code+Pro" {
		t.Fatal("failed to parse uri with embedded commas")
	}

}
