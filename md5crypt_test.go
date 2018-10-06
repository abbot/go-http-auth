package auth

import (
	"strings"
	"testing"
)

type md5entry struct {
	Magic, Salt, Hash []byte
}

func newEntry(e string) *md5entry {
	parts := strings.SplitN(e, "$", 4)
	if len(parts) != 4 {
		return nil
	}
	return &md5entry{
		Magic: []byte("$" + parts[1] + "$"),
		Salt:  []byte(parts[2]),
		Hash:  []byte(parts[3]),
	}
}

func Test_MD5Crypt(t *testing.T) {
	t.Parallel()
	testCases := [][]string{
		{"apache", "$apr1$J.w5a/..$IW9y6DR0oO/ADuhlMF5/X1"},
		{"pass", "$1$YeNsbWdH$wvOF8JdqsoiLix754LTW90"},
		{"topsecret", "$apr1$JI4wh3am$AmhephVqLTUyAVpFQeHZC0"},
	}
	for _, tc := range testCases {
		e := newEntry(tc[1])
		result := MD5Crypt([]byte(tc[0]), e.Salt, e.Magic)
		if string(result) != tc[1] {
			t.Fatalf("MD5Crypt returned '%s' instead of '%s'", string(result), tc[1])
		}
		t.Logf("MD5Crypt: '%s' (%s%s$) -> %s", tc[0], e.Magic, e.Salt, result)
	}
}
