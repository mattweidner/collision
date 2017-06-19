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
	"strings"
	"time"
)

type Message struct {
	count     int
	hash      string
	datablock []byte
}

var version int = 12
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
		fmt.Fprintf(os.Stderr, "\t-a <hash id> Hash algorithm.\n\t\tAvailable hash algorithms:\n\t\t0: md5\n\t\t1: sha1\n\t\t2: sha256\n\t\t3: sha512\n\t\t4: md4\n\t\t5: ripemd160\n\t\t6: sha3-224\n\t\t7: sha3-256\n\t\t8: sha3-384\n\t\t9: sha3-512\n")
		fmt.Fprintf(os.Stderr, "\t-p <prefix> Hash prefix to match.\n")
		fmt.Fprintf(os.Stderr, "\t-t <threads> Number of threads to spawn.\n")
		fmt.Fprintf(os.Stderr, "\nExample: %s -a 2 -p \"6517\" -t 4", os.Args[0])
	}
	flag.Parse()

	// Test for a user supplied prefix.
	if *hashPrefix == "" {
		fmt.Println("Missing prefix. Use -h for help.")
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
			fmt.Println("\nInvalid hash type. Use -h for help.\n")
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
				p = get16RandomBytes()
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
			fmt.Println("From data block (hex encoded):", hex.EncodeToString(m.datablock), "\n")
		}
	}
	fmt.Println("Processed", count, "total hashes.")
}

func get16RandomBytes() []byte {
	n0 := rand.Uint64() // 8 bytes
	n1 := rand.Uint64() // 8 bytes
	p := make([]byte, 8)
	q := make([]byte, 8)
	binary.LittleEndian.PutUint64(p, n0) // Convert Uint64 to byte array.
	binary.LittleEndian.PutUint64(q, n1)
	p = append(p, q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7])
	return p
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
	default:
		return nil, "Unknown"
	}
}
