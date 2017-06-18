package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"hash"
	"math/rand"
	"time"
)

var hasher hash.Hash
var version int = 4

func main() {
	// Program banner
	fmt.Println("Collision-inator!", version)

	// Set up command line arguments
	hashPrefix := flag.String("p", "", "Hash prefix to match.")
	hashChoice := flag.Int("m", 2, "Hash mode.\n\t0: md5\n\t1: sha1\n\t2: sha256\n\t3: sha512\n\t4: md4\n\t5: ripemd160\n\t6: sha3-224\n\t7: sha3-256\n\t8: sha3-384\n\t9: sha3-512")
	flag.Parse()

	// Test for a user supplied prefix to hunt for.
	if *hashPrefix == "" {
		fmt.Println("Missing prefix. Please specify a hash prefix to match.")
		return
	}
	fmt.Println("Hunting prefix:", *hashPrefix)

	// Seed PRNG
	rand.Seed(time.Time.UnixNano(time.Now()))

	// Brute force the hash algorithm until a hash is found that
	// matches the user supplied prefix.
	hashGuess := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for hashGuess[:(len(*hashPrefix))] != *hashPrefix {
		p := get16RandomBytes()
		setHash(*hashChoice)
		fmt.Println(p)
		hasher.Write(p)
		hashGuess = hex.EncodeToString(hasher.Sum(nil))
	}
	fmt.Println(hashGuess)
}

func get16RandomBytes() []byte {
	n0 := rand.Uint64()
	n1 := rand.Uint64()
	p := make([]byte, 8)
	q := make([]byte, 8)
	binary.LittleEndian.PutUint64(p, n0)
	binary.LittleEndian.PutUint64(q, n1)
	p = append(p, q[0])
	p = append(p, q[1])
	p = append(p, q[2])
	p = append(p, q[3])
	return p
}

func setHash(choice int) {
	switch choice {
	case 0:
		hasher = md5.New()
	case 1:
		hasher = sha1.New()
	case 2:
		hasher = sha256.New()
	case 3:
		hasher = sha512.New()
	case 4:
		hasher = md4.New()
	case 5:
		hasher = ripemd160.New()
	case 6:
		hasher = sha3.New224()
	case 7:
		hasher = sha3.New256()
	case 9:
		hasher = sha3.New384()
	case 10:
		hasher = sha3.New512()
	}
}
