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
	"os"
	"time"
)

var hasher hash.Hash
var version int = 9
var threads int = 2

func main() {
	// Program banner
	fmt.Println("Collision-inator! ver", version, "\n")

	// Set up command line arguments
	hashPrefix := flag.String("p", "", "Hash prefix to match.")
	hashChoice := flag.Int("a", 2, "Hash algorithm.")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]%s", os.Args[0], "\n")
		fmt.Fprintf(os.Stderr, "Options: %s", "\n")
		fmt.Fprintf(os.Stderr, "\t-a <hash id> Hash algorithm.\n\t\tAvailable hash algorithms:\n\t\t0: md5\n\t\t1: sha1\n\t\t2: sha256\n\t\t3: sha512\n\t\t4: md4\n\t\t5: ripemd160\n\t\t6: sha3-224\n\t\t7: sha3-256\n\t\t8: sha3-384\n\t\t9: sha3-512\n")
		fmt.Fprintf(os.Stderr, "\t-p <prefix> Hash prefix to match.\n")
		fmt.Fprintf(os.Stderr, "\nExample: %s -a 2 -p \"6517\"", os.Args[0])
	}
	flag.Parse()

	// Test for a user supplied prefix to hunt for.
	if *hashPrefix == "" {
		fmt.Println("Missing prefix. Use -h for help.")
		return
	}
	// Set hash type
	hasher = setHash(*hashChoice)
	fmt.Println("Hunting prefix:", *hashPrefix)
	if hasher == nil {
		fmt.Println("\nInvalid hash type. Use -h for help.\n")
		return
	}
	// Seed PRNG
	rand.Seed(time.Time.UnixNano(time.Now()))

	// Brute force the hash algorithm until a hash is found that
	// matches the user supplied prefix.
	hashGuess := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	p := []byte{00}
	c := 0
	for hashGuess[:(len(*hashPrefix))] != *hashPrefix {
		c++
		p = get16RandomBytes()
		hasher.Write(p)
		hashGuess = hex.EncodeToString(hasher.Sum(nil))
	}
	fmt.Println("")
	fmt.Println(hashGuess)
	fmt.Println("From data block:", p, "\n")
	fmt.Println("Processed", c, "hashes.")
}

func get16RandomBytes() []byte {
	n0 := rand.Uint64()
	n1 := rand.Uint64()
	p := make([]byte, 8)
	q := make([]byte, 8)
	binary.LittleEndian.PutUint64(p, n0)
	binary.LittleEndian.PutUint64(q, n1)
	p = append(p, q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7])
	return p
}

func setHash(choice int) hash.Hash {
	switch choice {
	case 0:
		fmt.Println("MD5")
		return md5.New()
	case 1:
		fmt.Println("SHA1")
		return sha1.New()
	case 2:
		fmt.Println("SHA256")
		return sha256.New()
	case 3:
		fmt.Println("SHA512")
		return sha512.New()
	case 4:
		fmt.Println("MD4")
		return md4.New()
	case 5:
		fmt.Println("RIPEMD160")
		return ripemd160.New()
	case 6:
		fmt.Println("SHA3-224")
		return sha3.New224()
	case 7:
		fmt.Println("SHA3-256")
		return sha3.New256()
	case 8:
		fmt.Println("SHA3-384")
		return sha3.New384()
	case 9:
		fmt.Println("SHA3-512")
		return sha3.New512()
	default:
		return nil
	}
}
