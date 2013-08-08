package auth

import "testing"
import "encoding/base64"
import "crypto/sha1"

func TestH(t *testing.T) {
	const hello = "Hello, world!"
	const hello_md5 = "6cd3556deb0da54bca060b4c39479839"
	h := H(hello)
	if h != hello_md5 {
		t.Fatal("Incorrect digest for test string:", h, "instead of", hello_md5)
	}
}

func TestGenMD5Password(t *testing.T) {
	const plaintext = "Hello, word!"
	passwd := GenMD5Password(plaintext)
	e := NewMD5Entry(passwd)
	if e == nil {
		t.Fatal("Invalid md5 formatting password:", passwd)
	}
	if passwd != string(MD5Crypt([]byte(plaintext), e.Salt, e.Magic)) {
		t.Fatal("Incorrect md5 formatting password:", passwd, "can't match with:", plaintext)
	}
}

func TestGenSHAPassword(t *testing.T) {
	const plaintext = "Hello, word!"
	passwd := GenSHAPassword(plaintext)
	d := sha1.New()
	d.Write([]byte(plaintext))
	if passwd[5:] != base64.StdEncoding.EncodeToString(d.Sum(nil)) {
		t.Fatal("Incorrect sha1 formatting password:", passwd, "can't match with:", plaintext)
	}
}
