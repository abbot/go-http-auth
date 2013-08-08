package auth

import "encoding/base64"
import "crypto/md5"
import "crypto/rand"
import "crypto/sha1"
import "fmt"
import mrand "math/rand"

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
Generate MD5 formatting password: $magic$salt$hash from plaintext
*/
func GenMD5Password(plaintext string) string {
	salt := RandomKey()
	magic := fmt.Sprintf("$%d$", mrand.Intn(100))
	passwd := MD5Crypt([]byte(plaintext), []byte(salt), []byte(magic))
	return string(passwd)
}

/*
Generate SHA1 formating password:{SHA}hash from plaintext
*/
func GenSHAPassword(plaintext string) string {
	h := sha1.New()
	h.Write([]byte(plaintext))
	bs := h.Sum(nil)
	passwd := base64.StdEncoding.EncodeToString(bs)
	return "{SHA}" + passwd

}
