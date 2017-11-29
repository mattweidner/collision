package main

/*
MIT License

Copyright (c) 2017 Matthew A. Weidner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/jzelinskie/whirlpool"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"hash"
	"math/rand"
	"os"
	"strings"
	"time"
)

type Message struct {
	count     int
	hash      string
	datablock []byte
}

var version int = 19
var done bool = false

func main() {
	// Program banner
	fmt.Printf("Collision-inator v%d\n", version)

	// Set up and parse command line arguments
	hashPrefix := flag.String("p", "", "Hash prefix to match.")
	hashChoice := flag.Int("a", 2, "Hash algorithm.")
	threads := flag.Int("t", 1, "Number of threads to spawn.")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]%s", os.Args[0], "\n")
		fmt.Fprintf(os.Stderr, "Options: %s", "\n")
		fmt.Fprintf(os.Stderr, "\t-a <hash id> Hash algorithm.\n\t\tAvailable hash algorithms:\n\t\t0: md5\n\t\t1: sha1\n\t\t2: sha256 (default)\n\t\t3: sha512\n\t\t4: md4\n\t\t5: ripemd160\n\t\t6: sha3-224\n\t\t7: sha3-256\n\t\t8: sha3-384\n\t\t9: sha3-512\n\t\t10: whirlpool\n")
		fmt.Fprintf(os.Stderr, "\t-p <prefix> Hash prefix to match.\n")
		fmt.Fprintf(os.Stderr, "\t-t <threads> Number of threads to spawn. (default: 1)\n")
		fmt.Fprintf(os.Stderr, "\nExample: MD5, search for prefix \"6517\", use 4 threads.\n")
		fmt.Fprintf(os.Stderr, "         %s -a 0 -p \"6517\" -t 4\n", os.Args[0])
	}
	flag.Parse()

	if len(os.Args) < 2 {
		flag.Usage()
		return
	}
	// Test for a user supplied prefix.
	if *hashPrefix == "" {
		fmt.Println("Missing prefix. Use -h for help.")
		return
	}
	*hashPrefix = fmt.Sprintf("%s", strings.ToLower(*hashPrefix))
	if validatePrefix(*hashPrefix) == false {
		fmt.Println("Prefix contains invalid characters.\nHashes should only contain hex digits (0-9, a-f, A-F).")
		return
	}
	fmt.Println("Hunting prefix:", *hashPrefix)

	// Seed PRNG
	rand.Seed(time.Time.UnixNano(time.Now()))

	// set up thread synchronization channel
	dataChan := make(chan Message)

	// Start threads
	for x := 0; x < *threads; x++ {
		// Set hash type
		hasher, hashName := setHash(*hashChoice)
		if hasher == nil {
			fmt.Println("\nInvalid hash type.\n")
			flag.Usage()
			return
		}
		// Thread function
		go func(hasher hash.Hash) {
			// Brute force the hash algorithm until a hash is found that
			// matches the user supplied prefix.
			hashGuess := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			p := []byte{00}
			c := 0
			// Loop until the prefix is found.
			for hashGuess[:(len(*hashPrefix))] != *hashPrefix {
				// done will be set true if another thread finds the prefix.
				if done {
					dataChan <- Message{c, "", []byte{}}
					return
				}
				c++
				hasher.Reset()
				p = get16RandomChars()
				hasher.Write(p)
				hashGuess = hex.EncodeToString(hasher.Sum(nil))
			}
			// Prefix is found!
			done = true
			dataChan <- Message{c, strings.Join([]string{hashName, hashGuess}, ": "), p}
		}(hasher)
	}
	count := 0
	fmt.Println("")
	// Gather data from all the threads.
	for x := 0; x < *threads; x++ {
		m := <-dataChan
		count = count + m.count
		if m.hash != "" {
			fmt.Println(m.hash)
			fmt.Println("From string:", string(m.datablock), "\n")
		}
	}
	fmt.Println("Processed", count, "total hashes.")
}

func get16RandomChars() []byte {
	var r []byte
	dictionary := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvqxyz0123456789"
	l := len(dictionary) - 1
	for i := 0; i < 16; i++ {
		r = append(r, dictionary[rand.Intn(l)])
	}
	return r
}

func setHash(choice int) (hash.Hash, string) {
	switch choice {
	case 0:
		return md5.New(), "MD5"
	case 1:
		return sha1.New(), "SHA1"
	case 2:
		return sha256.New(), "SHA256"
	case 3:
		return sha512.New(), "SHA512"
	case 4:
		return md4.New(), "MD4"
	case 5:
		return ripemd160.New(), "RIPEMD160"
	case 6:
		return sha3.New224(), "SHA3-224"
	case 7:
		return sha3.New256(), "SHA3-256"
	case 8:
		return sha3.New384(), "SHA3-384"
	case 9:
		return sha3.New512(), "SHA3-512"
	case 10:
		return whirlpool.New(), "WHIRLPOOL"
	default:
		return nil, "Unknown"
	}
}

func validatePrefix(prefix string) bool {
	var hexDigits string = "0123456789abcdef"
	for _, c := range prefix {
		for i, d := range hexDigits {
			if c != d && i == len(hexDigits)-1 {
				return false
			}
			if c == d {
				break
			}
		}
	}
	return true
}
