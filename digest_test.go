package auth

import (
	"testing"
	"http"
	"time"
)

func TestAuthDigest(t *testing.T) {
	secrets := HtdigestFileProvider("test.htdigest")
	da := &DigestAuth{Opaque: "f5f248692a57f26ea430abeef2051c7a",
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
	r.Header.Set("Authorization", `Digest username="test", realm="example.com", nonce="954dc0a95652bc4ac12270f1394d6661", uri="/", cnonce="NDk0MzU2", nc=00000001, qop="auth", response="00f37cc3866798916ce0186fe8b4e8f0", opaque="f5f248692a57f26ea430abeef2051c7a", algorithm="MD5"`)
	if u, _ := da.CheckAuth(r); u != "" {
		t.Fatal("non-empty auth for unknown client")
	}

	da.clients["954dc0a95652bc4ac12270f1394d6661"] = &digest_client{nc: 0, last_seen: time.Nanoseconds()}
	if u, _ := da.CheckAuth(r); u != "test" {
		t.Fatal("empty auth for legitimate client")
	}
	if u, _ := da.CheckAuth(r); u != "" {
		t.Fatal("non-empty auth for outdated nc")
	}
}
