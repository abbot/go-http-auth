package auth

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestAuthDigest(t *testing.T) {
	t.Parallel()
	secrets := HtdigestFileProvider("test.htdigest")
	da := &DigestAuth{Opaque: "U7H+ier3Ae8Skd/g",
		Realm:   "example.com",
		Secrets: secrets,
		clients: map[string]*digestClient{}}
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
	r.Header.Set("Authorization", `Digest username="test", realm="example.com", nonce="Vb9BP/h81n3GpTTB", uri="/t2", cnonce="NjE4MTM2", nc=00000001, qop="auth", response="ffc357c4eba74773c8687e0bc724c9a3", opaque="U7H+ier3Ae8Skd/g", algorithm=MD5`)
	if u, _ := da.CheckAuth(r); u != "" {
		t.Fatal("non-empty auth for unknown client")
	}

	r.URL, _ = url.Parse("/t2")
	da.clients["Vb9BP/h81n3GpTTB"] = &digestClient{nc: 0, lastSeen: time.Now().UnixNano()}
	if u, _ := da.CheckAuth(r); u != "test" {
		t.Fatal("empty auth for legitimate client")
	}

	// our nc is now 0, client nc is 1
	if u, _ := da.CheckAuth(r); u != "" {
		t.Fatal("non-empty auth for outdated nc")
	}

	// try again with nc checking off
	da.IgnoreNonceCount = true
	if u, _ := da.CheckAuth(r); u != "test" {
		t.Fatal("empty auth for outdated nc even though nc checking is off")
	}
	da.IgnoreNonceCount = false

	r.URL, _ = url.Parse("/")
	da.clients["Vb9BP/h81n3GpTTB"] = &digestClient{nc: 0, lastSeen: time.Now().UnixNano()}
	if u, _ := da.CheckAuth(r); u != "" {
		t.Fatal("non-empty auth for bad request path")
	}

	r.URL, _ = url.Parse("/t3")
	da.clients["Vb9BP/h81n3GpTTB"] = &digestClient{nc: 0, lastSeen: time.Now().UnixNano()}
	if u, _ := da.CheckAuth(r); u != "" {
		t.Fatal("non-empty auth for bad request path")
	}

	da.clients["+RbVXSbIoa1SaJk1"] = &digestClient{nc: 0, lastSeen: time.Now().UnixNano()}
	r.Header.Set("Authorization", `Digest username="test", realm="example.com", nonce="+RbVXSbIoa1SaJk1", uri="/", cnonce="NjE4NDkw", nc=00000001, qop="auth", response="c08918024d7faaabd5424654c4e3ad1c", opaque="U7H+ier3Ae8Skd/g", algorithm=MD5`)
	if u, _ := da.CheckAuth(r); u != "test" {
		t.Fatal("empty auth for valid request in subpath")
	}
}

func TestDigestAuthParams(t *testing.T) {
	t.Parallel()
	const authorization = `Digest username="test", realm="", nonce="FRPnGdb8lvM1UHhi", uri="/css?family=Source+Sans+Pro:400,700,400italic,700italic|Source+Code+Pro", algorithm=MD5, response="fdcdd78e5b306ffed343d0ec3967f2e5", opaque="lEgVjogmIar2fg/t", qop=auth, nc=00000001, cnonce="e76b05db27a3b323"`

	params := DigestAuthParams(authorization)
	want := "/css?family=Source+Sans+Pro:400,700,400italic,700italic|Source+Code+Pro"
	if params["uri"] != want {
		t.Fatalf("failed to parse uri with embedded commas, got %q want %q", params["uri"], want)
	}
}

func TestNewContextNoDeadlock(t *testing.T) {
	t.Parallel()
	const (
		realm = "example.com"
		user  = "user"
	)
	secrets := func(u, r string) string {
		if u == user && r == realm {
			return "aa78524fceb0e50fd8ca96dd818b8cf9"
		}
		return ""
	}
	da := NewDigestAuthenticator(realm, secrets)
	da.ClientCacheSize = 10
	da.ClientCacheTolerance = 1
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		ctx := context.Background()
		req, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			t.Fatalf("Failed to create http.Request: %v", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			done := make(chan struct{})
			go func() {
				da.NewContext(ctx, req)
				close(done)
			}()
			select {
			case <-done:
				return
			case <-time.After(time.Second):
				t.Error("deadlock detected")
			}
		}()
	}
	wg.Wait()
}
