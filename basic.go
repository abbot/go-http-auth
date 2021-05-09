package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type compareFunc func(hashedPassword, password []byte) error

const (
	shaEncoding      = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	cryptPassDelim   = "$"
	cryptPassRounds  = "rounds="
	shaRoundsDefault = uint(5_000)
	shaRoundsMin     = uint(1_000)
	shaRoundsMax     = uint(999_999_999)
)

var (
	errMismatchedHashAndPassword = errors.New("mismatched hash and password")

	compareFuncs = []struct {
		prefix  string
		compare compareFunc
	}{
		{"", compareMD5HashAndPassword}, // default compareFunc
		{"{SHA}", compareShaHashAndPassword},
		{"$5$", compareShaCryptHashAndPassword},
		{"$6$", compareShaCryptHashAndPassword},
		// Bcrypt is complicated. According to crypt(3) from
		// crypt_blowfish version 1.3 (fetched from
		// http://www.openwall.com/crypt/crypt_blowfish-1.3.tar.gz), there
		// are three different has prefixes: "$2a$", used by versions up
		// to 1.0.4, and "$2x$" and "$2y$", used in all later
		// versions. "$2a$" has a known bug, "$2x$" was added as a
		// migration path for systems with "$2a$" prefix and still has a
		// bug, and only "$2y$" should be used by modern systems. The bug
		// has something to do with handling of 8-bit characters. Since
		// both "$2a$" and "$2x$" are deprecated, we are handling them the
		// same way as "$2y$", which will yield correct results for 7-bit
		// character passwords, but is wrong for 8-bit character
		// passwords. You have to upgrade to "$2y$" if you want sant 8-bit
		// character password support with bcrypt. To add to the mess,
		// OpenBSD 5.5. introduced "$2b$" prefix, which behaves exactly
		// like "$2y$" according to the same source.
		{"$2a$", bcrypt.CompareHashAndPassword},
		{"$2b$", bcrypt.CompareHashAndPassword},
		{"$2x$", bcrypt.CompareHashAndPassword},
		{"$2y$", bcrypt.CompareHashAndPassword},
	}

	shaHashAlgo = map[string]crypto.Hash{
		"5": crypto.SHA256,
		"6": crypto.SHA512,
	}
	shaHashDigestBytes = map[crypto.Hash][]uint8{
		crypto.SHA256: {
			0, 10, 20, 21, 1, 11, 12, 22, 2, 3, 13, 23, 24, 4, 14, 15, 25, 5,
			6, 16, 26, 27, 7, 17, 18, 28, 8, 9, 19, 29, 31, 30,
		},
		crypto.SHA512: {
			0, 21, 42, 22, 43, 1, 44, 2, 23, 3, 24, 45, 25, 46, 4, 47, 5, 26,
			6, 27, 48, 28, 49, 7, 50, 8, 29, 9, 30, 51, 31, 52, 10, 53, 11, 32,
			12, 33, 54, 34, 55, 13, 56, 14, 35, 15, 36, 57, 37, 58, 16, 59, 17, 38,
			18, 39, 60, 40, 61, 19, 62, 20, 41, 63,
		},
	}
	cryptPassStructureError = errors.New("hashed password structure mismatch")
)

// BasicAuth is an authenticator implementation for 'Basic' HTTP
// Authentication scheme (RFC 7617).
type BasicAuth struct {
	Realm   string
	Secrets SecretProvider
	// Headers used by authenticator. Set to ProxyHeaders to use with
	// proxy server. When nil, NormalHeaders are used.
	Headers *Headers
}

// check that BasicAuth implements AuthenticatorInterface
var _ = (AuthenticatorInterface)((*BasicAuth)(nil))

// CheckAuth checks the username/password combination from the
// request. Returns either an empty string (authentication failed) or
// the name of the authenticated user.
func (a *BasicAuth) CheckAuth(r *http.Request) string {
	user, password, ok := r.BasicAuth()
	if !ok {
		return ""
	}

	secret := a.Secrets(user, a.Realm)
	if secret == "" {
		return ""
	}

	if !CheckSecret(password, secret) {
		return ""
	}

	return user
}

// CheckSecret returns true if the password matches the encrypted
// secret.
func CheckSecret(password, secret string) bool {
	compare := compareFuncs[0].compare
	for _, cmp := range compareFuncs[1:] {
		if strings.HasPrefix(secret, cmp.prefix) {
			compare = cmp.compare
			break
		}
	}
	return compare([]byte(secret), []byte(password)) == nil
}

func compareShaHashAndPassword(hashedPassword, password []byte) error {
	d := sha1.New()
	d.Write(password)
	if subtle.ConstantTimeCompare(hashedPassword[5:], []byte(base64.StdEncoding.EncodeToString(d.Sum(nil)))) != 1 {
		return errMismatchedHashAndPassword
	}
	return nil
}

func compareShaCryptHashAndPassword(hashedPassword, password []byte) error {
	hash, rounds, defaultRounds, salt, _, err := dissectShaCryptHash(hashedPassword)
	if err != nil {
		return errMismatchedHashAndPassword
	}

	result, err := shaCryptPassword(hash, password, salt, rounds, defaultRounds)
	if err != nil || subtle.ConstantTimeCompare(hashedPassword, result) != 1 {
		return errMismatchedHashAndPassword
	}

	return nil
}

// dissectShaCryptHash splits SHA-256/512 password hash into it's parts.
// optional 'rounds=N$' is signaled
func dissectShaCryptHash(hashedPassword []byte) (crypto.Hash, uint, bool, []byte, []byte, error) {
	rounds := shaRoundsDefault
	defaultRounds := true
	parts := bytes.Split(hashedPassword, []byte(cryptPassDelim))
	offset := 0

	if len(parts) < 4 {
		return 0, 0, false, nil, nil, cryptPassStructureError
	}

	if len(parts) > 4 {
		if len(parts) != 5 || !bytes.HasPrefix(parts[2], []byte(cryptPassRounds)) {
			return 0, 0, false, nil, nil, cryptPassStructureError
		}

		offset += 1
		defaultRounds = false
		i, e := strconv.ParseUint(string(bytes.TrimPrefix(parts[2], []byte(cryptPassRounds))), 10, 32)

		if e != nil {
			return 0, 0, false, nil, nil, cryptPassStructureError
		}

		// 'i' is uint64 but parsed to fit into 32 bit and 'rounds' as uint is at least 32 bit
		rounds = uint(i)
		if rounds < shaRoundsMin {
			rounds = shaRoundsMin
		}
		if rounds > shaRoundsMax {
			rounds = shaRoundsMax
		}
	}

	if hash, ok := shaHashAlgo[string(parts[1])]; !ok {
		return 0, 0, false, nil, nil, cryptPassStructureError
	} else {
		salt := parts[2+offset]
		digest := parts[3+offset]

		return hash, rounds, defaultRounds, salt, digest, nil
	}
}

// Implements SHA-crypt, as openssl does, following instructions in
// https://www.akkadia.org/drepper/SHA-crypt.txt
// It's 21 complex digest creating steps, so expect nothing easy to read
func shaCryptPassword(hash crypto.Hash, password, salt []byte, rounds uint, defaultRounds bool) ([]byte, error) {
	// #1 - #3
	A := hash.New()
	A.Write(password)
	A.Write(salt)

	// #4 - #8
	B := hash.New()
	B.Write(password)
	B.Write(salt)
	B.Write(password)
	BDigest := B.Sum(nil)

	// #9
	i := len(password)
	for ; i > hash.Size(); i -= hash.Size() {
		A.Write(BDigest)
	}
	// #10
	A.Write(BDigest[:i])

	// #11
	for i = len(password); i > 0; i >>= 1 {
		// last bit is set to 1
		if i&1 != 0 {
			A.Write(BDigest)
		} else {
			A.Write(password)
		}
	}

	// #12
	ADigest := A.Sum(nil)

	// #13 - #15
	DP := hash.New()
	for i = 0; i < len(password); i++ {
		DP.Write(password)
	}
	DPDigest := DP.Sum(nil)

	// #16
	i = len(password)
	P := make([]byte, 0, i)
	for ; i > hash.Size(); i -= hash.Size() {
		P = append(P, DPDigest...)
	}
	P = append(P, DPDigest[:i]...)

	// #17 - #19
	DS := hash.New()
	times := 16 + uint8(ADigest[0])
	for ; times > 0; times-- {
		DS.Write(salt)
	}
	DSDigest := DS.Sum(nil)

	// #20
	i = len(salt)
	S := make([]byte, 0, i)
	for ; i > hash.Size(); i -= hash.Size() {
		S = append(S, DSDigest...)
	}
	S = append(S, DSDigest[:i]...)

	// #21
	var finalDigest = ADigest
	for rCount := uint(0); rCount < rounds; rCount++ {
		R := hash.New()
		var seq []byte
		if rCount%2 != 0 {
			seq = P
		} else {
			seq = finalDigest
		}
		R.Write(seq)
		if rCount%3 != 0 {
			R.Write(S)
		}
		if rCount%7 != 0 {
			R.Write(P)
		}
		if rCount%2 != 0 {
			R.Write(finalDigest)
		} else {
			R.Write(P)
		}
		RDigest := R.Sum(nil)
		finalDigest = RDigest
	}

	if mapping, ok := shaHashDigestBytes[hash]; !ok {
		return nil, errors.New("unable to map SHA digest")
	} else {
		result := make([]byte, len(mapping))
		for i = 0; i < len(mapping); i++ {
			result[i] = finalDigest[mapping[i]]
		}

		hString := func(h crypto.Hash) string {
			for k, v := range shaHashAlgo {
				if v == h {
					return k
				}
			}
			return "0"
		}
		rString := func(d bool) string {
			if !d {
				return fmt.Sprintf("rounds=%d%s", rounds, cryptPassDelim)
			}
			return ""
		}

		// #22
		return []byte(
			fmt.Sprintf(
				cryptPassDelim+"%s"+cryptPassDelim+"%s%s"+cryptPassDelim+"%s",
				hString(hash), rString(defaultRounds), string(salt[:16]), string(shaBase64Encode(result)),
			)), nil
	}
}

// shaBase64Encode is used to encode SHA-256 or SHA-512 digests into
// base 64 bytes, following SHA-crypt encoding rules.
// While default Base64 operates LTR SHA-crypt works RTL.
func shaBase64Encode(src []byte) (dst []byte) {
	dst = make([]byte, ((len(src)*8)+5)/6)

	si, di := 0, 0
	n := (len(src) / 3) * 3
	for si < n {
		val := uint(src[si])<<16 | uint(src[si+1])<<8 | uint(src[si+2])
		dst[di] = shaEncoding[val&0x3f]
		dst[di+1] = shaEncoding[(val>>6)&0x3f]
		dst[di+2] = shaEncoding[(val>>12)&0x3f]
		dst[di+3] = shaEncoding[(val>>18)&0x3f]

		si += 3
		di += 4
	}

	remain := len(src) - si
	val := uint(0)
	switch remain {
	case 0:
		return
	case 1:
		val = uint(src[si])
	case 2:
		val = uint(src[si])<<8 | uint(src[si+1])
	}
	dst[di] = shaEncoding[val&0x3f]
	dst[di+1] = shaEncoding[(val>>6)&0x3f]
	if remain == 2 {
		dst[di+2] = shaEncoding[(val>>12)&0x3f]
	}

	return
}

func compareMD5HashAndPassword(hashedPassword, password []byte) error {
	parts := bytes.SplitN(hashedPassword, []byte("$"), 4)
	if len(parts) != 4 {
		return errMismatchedHashAndPassword
	}
	magic := []byte("$" + string(parts[1]) + "$")
	salt := parts[2]
	if subtle.ConstantTimeCompare(hashedPassword, MD5Crypt(password, salt, magic)) != 1 {
		return errMismatchedHashAndPassword
	}
	return nil
}

// RequireAuth is an http.HandlerFunc for BasicAuth which initiates
// the authentication process (or requires reauthentication).
func (a *BasicAuth) RequireAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contentType, a.Headers.V().UnauthContentType)
	w.Header().Set(a.Headers.V().Authenticate, `Basic realm="`+a.Realm+`"`)
	w.WriteHeader(a.Headers.V().UnauthCode)
	w.Write([]byte(a.Headers.V().UnauthResponse))
}

// Wrap returns an http.HandlerFunc, which wraps
// AuthenticatedHandlerFunc with this BasicAuth authenticator's
// authentication checks. Once the request contains valid credentials,
// it calls wrapped AuthenticatedHandlerFunc.
//
// Deprecated: new code should use NewContext instead.
func (a *BasicAuth) Wrap(wrapped AuthenticatedHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if username := a.CheckAuth(r); username == "" {
			a.RequireAuth(w, r)
		} else {
			ar := &AuthenticatedRequest{Request: *r, Username: username}
			wrapped(w, ar)
		}
	}
}

// NewContext returns a context carrying authentication information for the request.
func (a *BasicAuth) NewContext(ctx context.Context, r *http.Request) context.Context {
	info := &Info{Username: a.CheckAuth(r), ResponseHeaders: make(http.Header)}
	info.Authenticated = (info.Username != "")
	if !info.Authenticated {
		info.ResponseHeaders.Set(a.Headers.V().Authenticate, `Basic realm="`+a.Realm+`"`)
	}
	return context.WithValue(ctx, infoKey, info)
}

// NewBasicAuthenticator returns a BasicAuth initialized with provided
// realm and secrets.
//
// Deprecated: new code should construct BasicAuth values directly.
func NewBasicAuthenticator(realm string, secrets SecretProvider) *BasicAuth {
	return &BasicAuth{Realm: realm, Secrets: secrets}
}
