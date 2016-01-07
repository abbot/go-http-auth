package auth

import (
	"encoding/base64"
	"net/http"
	"testing"
)

func TestAuthBasic(t *testing.T) {
	secrets := HtpasswdFileProvider("test.htpasswd")

	for _, isProxy := range []bool{false, true} {
		a := &BasicAuth{IsProxy: isProxy, Realm: "example.com", Secrets: secrets}
		r := &http.Request{}
		r.Method = "GET"
		if a.CheckAuth(r) != "" {
			t.Fatal("CheckAuth passed on empty headers")
		}
		r.Header = http.Header(make(map[string][]string))
		r.Header.Set(AuthorizationHeaderName(a.IsProxy), "Digest blabla ololo")
		if a.CheckAuth(r) != "" {
			t.Fatal("CheckAuth passed on bad headers")
		}
		r.Header.Set(AuthorizationHeaderName(a.IsProxy), "Basic !@#")
		if a.CheckAuth(r) != "" {
			t.Fatal("CheckAuth passed on bad base64 data")
		}

		data := [][]string{
			{"test", "hello"},
			{"test2", "hello2"},
			{"test3", "hello3"},
			{"test16", "topsecret"},
		}
		for _, tc := range data {
			auth := base64.StdEncoding.EncodeToString([]byte(tc[0] + ":" + tc[1]))
			r.Header.Set(AuthorizationHeaderName(a.IsProxy), "Basic "+auth)
			if a.CheckAuth(r) != tc[0] {
				t.Fatalf("CheckAuth failed for user '%s'", tc[0])
			}
		}
	}
}
