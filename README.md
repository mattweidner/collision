# collision
A multithreaded hash collision brute forcing utility.

Generates cryptographic hashes of randomly selected 16-byte paylods until
a match is found with a user defined partial (or full) hash.

Supported hashes:
* MD5
* SHA1
* SHA256
* SHA512
* MD4
* RIPEMD160
* SHA3-224
* SHA3-256
* SHA3-384
* SHA3-512

# Usage
```
Collision-inator v14
Usage: collision [options]
Options:
        -a <hash id> Hash algorithm.
                Available hash algorithms:
                0: md5
                1: sha1
                2: sha256 (default)
                3: sha512
                4: md4
                5: ripemd160
                6: sha3-224
                7: sha3-256
                8: sha3-384
                9: sha3-512
        -p <prefix> Hash prefix to match.
        -t <threads> Number of threads to spawn. (default: 1)

Example: MD5, search for prefix "6517", use 4 threads.
         collision -a 0 -p "6517" -t 4
```

# License

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
