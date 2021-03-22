package auth

import (
	"reflect"
	"testing"
)

func TestH(t *testing.T) {
	t.Parallel()
	const hello = "Hello, world!"
	const helloMD5 = "6cd3556deb0da54bca060b4c39479839"
	h := H(hello)
	if h != helloMD5 {
		t.Fatal("Incorrect digest for test string:", h, "instead of", helloMD5)
	}
}

func TestParsePairs(t *testing.T) {
	t.Parallel()
	const header = `username="\test", realm="a \"quoted\" string", nonce="FRPnGdb8lvM1UHhi", uri="/css?family=Source+Sans+Pro:400,700,400italic,700italic|Source+Code+Pro", algorithm=MD5, response="fdcdd78e5b306ffed343d0ec3967f2e5", opaque="lEgVjogmIar2fg/t", qop=auth, nc=00000001, cnonce="e76b05db27a3b323", empty1=, empty2=""`

	want := map[string]string{
		"username":  "test",
		"realm":     `a "quoted" string`,
		"nonce":     "FRPnGdb8lvM1UHhi",
		"uri":       "/css?family=Source+Sans+Pro:400,700,400italic,700italic|Source+Code+Pro",
		"algorithm": "MD5",
		"response":  "fdcdd78e5b306ffed343d0ec3967f2e5",
		"opaque":    "lEgVjogmIar2fg/t",
		"qop":       "auth",
		"nc":        "00000001",
		"cnonce":    "e76b05db27a3b323",
		"empty1":    "",
		"empty2":    "",
	}
	got := ParsePairs(header)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("failed to correctly parse pairs, got %v, want %v", got, want)
	}
}
