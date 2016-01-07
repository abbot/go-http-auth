package auth

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

/*
 Return a random 16-byte base64 alphabet string
*/
func RandomKey() string {
	k := make([]byte, 12)
	for bytes := 0; bytes < len(k); {
		n, err := rand.Read(k[bytes:])
		if err != nil {
			panic("rand.Read() failed")
		}
		bytes += n
	}
	return base64.StdEncoding.EncodeToString(k)
}

/*
 H function for MD5 algorithm (returns a lower-case hex MD5 digest)
*/
func H(data string) string {
	digest := md5.New()
	digest.Write([]byte(data))
	return fmt.Sprintf("%x", digest.Sum(nil))
}

/*
 ParseList parses a comma-separated list of values as described by RFC 2068.
 which was itself ported from urllib2.parse_http_list, from the Python standard library.
 Lifted from https://code.google.com/p/gorilla/source/browse/http/parser/parser.go
*/
func ParseList(value string) []string {
	var list []string
	var escape, quote bool
	b := new(bytes.Buffer)
	for _, r := range value {
		if escape {
			b.WriteRune(r)
			escape = false
			continue
		}
		if quote {
			if r == '\\' {
				escape = true
				continue
			} else if r == '"' {
				quote = false
			}
			b.WriteRune(r)
			continue
		}
		if r == ',' {
			list = append(list, strings.TrimSpace(b.String()))
			b.Reset()
			continue
		}
		if r == '"' {
			quote = true
		}
		b.WriteRune(r)
	}
	// Append last part.
	if s := b.String(); s != "" {
		list = append(list, strings.TrimSpace(s))
	}
	return list
}

/*
 ParsePairs extracts key/value pairs from a comma-separated list of values as
 described by RFC 2068.
 The resulting values are unquoted. If a value doesn't contain a "=", the
 key is the value itself and the value is an empty string.
 Lifted from https://code.google.com/p/gorilla/source/browse/http/parser/parser.go
*/
func ParsePairs(value string) map[string]string {
	m := make(map[string]string)
	for _, pair := range ParseList(strings.TrimSpace(value)) {
		if i := strings.Index(pair, "="); i < 0 {
			m[pair] = ""
		} else {
			v := pair[i+1:]
			if v[0] == '"' && v[len(v)-1] == '"' {
				// Unquote it.
				v = v[1 : len(v)-1]
			}
			m[pair[:i]] = v
		}
	}
	return m
}
