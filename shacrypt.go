package auth

import (
	"bytes"
	"crypto"
	"errors"
	"strconv"
)

type SHAHash struct {
	Hash          crypto.Hash
	Magic         []byte
	Rounds        uint
	DefaultRounds bool
	Salt          []byte
	Digest        []byte
}

type SHACryptAlgo struct {
	algo  crypto.Hash
	swaps []uint8
}

const (
	shaEncoding      = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	cryptPassDelim   = "$"
	cryptPassRounds  = "rounds="
	shaRoundsDefault = uint(5000)
	shaRoundsMin     = uint(1000)
	shaRoundsMax     = uint(999999999)
)

var (
	shaCryptAlgo = map[string]*SHACryptAlgo{
		"$5$": {crypto.SHA256, []uint8{
			20, 10, 0, 11, 1, 21, 2, 22, 12, 23, 13, 3, 14, 4, 24, 5, 25, 15,
			26, 16, 6, 17, 7, 27, 8, 28, 18, 29, 19, 9, 30, 31,
		}},
		"$6$": {crypto.SHA512, []uint8{
			42, 21, 0, 1, 43, 22, 23, 2, 44, 45, 24, 3, 4, 46, 25, 26, 5, 47,
			48, 27, 6, 7, 49, 28, 29, 8, 50, 51, 30, 9, 10, 52, 31, 32, 11, 53,
			54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15, 16, 58, 37, 38, 17, 59,
			60, 39, 18, 19, 61, 40, 41, 20, 62, 63,
		}},
	}

	cryptPassStructureError    = errors.New("hashed password structure mismatch")
	missingByteSwapMapperError = errors.New("unable to map SHA digest")
)

// SHACrypt implements SHA-crypt, as openssl does, following instructions in
// https://www.akkadia.org/drepper/SHA-crypt.txt
// It's 21 complex digest creating steps, so expect nothing easy to read.
func SHACrypt(hash crypto.Hash, password, salt, magic []byte, rounds uint, defaultRounds bool) ([]byte, error) {
	// #1 - #3
	A := hash.New()
	A.Write(password)
	A.Write(salt)

	intermediate := make([]byte, 0, hash.Size())
	// #4 - #8
	B := hash.New()
	B.Write(password)
	B.Write(salt)
	B.Write(password)
	intermediate = B.Sum(intermediate[:0])

	// #9
	i := len(password)
	for ; i > hash.Size(); i -= hash.Size() {
		A.Write(intermediate)
	}
	// #10
	A.Write(intermediate[:i])

	// #11
	for i = len(password); i > 0; i >>= 1 {
		// last bit is set to 1
		if i&1 != 0 {
			A.Write(intermediate)
		} else {
			A.Write(password)
		}
	}

	// #12
	ADigest := A.Sum(nil)

	// #13 - #15
	B.Reset()
	DP := B
	for i = 0; i < len(password); i++ {
		DP.Write(password)
	}
	intermediate = DP.Sum(intermediate[:0])

	// #16
	i = len(password)
	P := make([]byte, 0, i)
	for ; i > hash.Size(); i -= hash.Size() {
		P = append(P, intermediate...)
	}
	P = append(P, intermediate[:i]...)

	// #17 - #19
	B.Reset()
	DS := B
	times := 16 + uint8(ADigest[0])
	for ; times > 0; times-- {
		DS.Write(salt)
	}
	intermediate = DS.Sum(intermediate[:0])

	// #20
	i = len(salt)
	S := make([]byte, 0, i)
	for ; i > hash.Size(); i -= hash.Size() {
		S = append(S, intermediate...)
	}
	S = append(S, intermediate[:i]...)

	// #21
	finalDigest := append(intermediate[:0], ADigest...)
	for rCount := uint(0); rCount < rounds; rCount++ {
		B.Reset()
		R := B
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
		finalDigest = R.Sum(finalDigest[:0])
	}

	mapping, err := getSwapBytes(string(magic))
	if err != nil {
		return nil, missingByteSwapMapperError
	}

	digestLength := encodedLength(hash)
	result := make([]byte, 0, 37+digestLength)
	// #22 a)
	result = append(result, magic...)
	// #22 b)
	if !defaultRounds {
		result = append(strconv.AppendUint(append(result, []byte("rounds")...), uint64(rounds), 10), cryptPassDelim...)
	}
	// #22 c) + d)
	result = append(append(result, salt[:16]...), cryptPassDelim...)
	// #22 e) result
	// base64 encode following sha-crypt rules [#22 e)]
	v := uint(0)
	bits := uint(0)
	for _, idx := range mapping {
		v |= uint(finalDigest[idx]) << bits
		for bits = bits + 8; bits > 6; bits -= 6 {
			result = append(result, shaEncoding[v&0x3f])
			v >>= 6
		}
	}
	result = append(result, shaEncoding[v&0x3f])

	return result, nil
}

// DissectShaCryptHash splits SHA-256/512 password hash into it's parts.
// optional 'rounds=N$' is signaled
func DissectShaCryptHash(hashedPassword []byte) (*SHAHash, error) {
	rounds := shaRoundsDefault
	defaultRounds := true
	parts := bytes.Split(hashedPassword, []byte(cryptPassDelim))
	offset := 0

	if len(parts) < 4 {
		return nil, cryptPassStructureError
	}

	if len(parts) > 4 {
		if len(parts) != 5 || !bytes.HasPrefix(parts[2], []byte(cryptPassRounds)) {
			return nil, cryptPassStructureError
		}

		offset += 1
		defaultRounds = false
		i, e := strconv.ParseUint(string(bytes.TrimPrefix(parts[2], []byte(cryptPassRounds))), 10, 32)

		if e != nil {
			return nil, cryptPassStructureError
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

	magic := make([]byte, 0, 2*len(cryptPassDelim) + len(parts[1]))
	magic = append(append(append(magic, cryptPassDelim...), parts[1]...), cryptPassDelim...)

	if hash, err := getHash(string(magic)); err != nil {
		return nil, cryptPassStructureError
	} else {
		salt := parts[2+offset]
		digest := parts[3+offset]

		if len(digest) != encodedLength(hash) {
			return nil, cryptPassStructureError
		}

		result := SHAHash{hash, magic, rounds, defaultRounds, salt, digest}
		return &result, nil
	}
}

func encodedLength(h crypto.Hash) int {
	return ((h.Size() * 8) + 5) / 6
}

func getHash(magic string) (crypto.Hash, error) {
	if a, ok := shaCryptAlgo[magic]; ok {
		return a.algo, nil
	}
	return 0, errors.New("unable to gather hash algorithm")
}

func getSwapBytes(magic string) ([]uint8, error) {
	if a, ok := shaCryptAlgo[magic]; ok {
		return a.swaps, nil
	}
	return nil, errors.New("unable to gather hash specific bytes swapping")
}
