package auth

import (
	"fmt"
	"reflect"
	"testing"
)

func TestH(t *testing.T) {
	const hello = "Hello, world!"
	const hello_md5 = "6cd3556deb0da54bca060b4c39479839"
	h := H(hello)
	if h != hello_md5 {
		t.Fatal("Incorrect digest for test string:", h, "instead of", hello_md5)
	}
}

func TestParsePairs(t *testing.T) {
	const header = `username="test", realm="", nonce="FRPnGdb8lvM1UHhi", uri="/css?family=Source+Sans+Pro:400,700,400italic,700italic|Source+Code+Pro", algorithm=MD5, response="fdcdd78e5b306ffed343d0ec3967f2e5", opaque="lEgVjogmIar2fg/t", qop=auth, nc=00000001, cnonce="e76b05db27a3b323"`

	expected := map[string]string{
		"username":  "test",
		"realm":     "",
		"nonce":     "FRPnGdb8lvM1UHhi",
		"uri":       "/css?family=Source+Sans+Pro:400,700,400italic,700italic|Source+Code+Pro",
		"algorithm": "MD5",
		"response":  "fdcdd78e5b306ffed343d0ec3967f2e5",
		"opaque":    "lEgVjogmIar2fg/t",
		"qop":       "auth",
		"nc":        "00000001",
		"cnonce":    "e76b05db27a3b323",
	}

	res := ParsePairs(header)

	if !reflect.DeepEqual(res, expected) {
		fmt.Printf("%#v\n", res)
		t.Fatal("Failed to correctly parse pairs")
	}

}
