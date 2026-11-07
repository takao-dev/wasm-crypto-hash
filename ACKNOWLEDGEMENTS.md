# Acknowledgements & Third-Party Credits

## BIP-0039 English wordlist

`lib/bip39English.ts` vendors the complete 2048-word English list from
https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt.
BIP-0039 authors: Marek Palatinus, Pavol Rusnak, Aaron Voisine and Sean Bowe.
The specification declares the MIT License: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

This library builds upon and is inspired by the work of multiple open-source cryptographic engineers and contributors.

## Upstream & Base Implementations
- **hash-wasm** (c) 2020 Dani Biró (MIT License)

## Embedded C Implementations & Original Algorithm Authors
Embedded C implementations located in `/src` may carry original permissive open-source licenses (Public Domain, BSD, Apache, MIT). We extend our sincere gratitude to the original algorithm authors:

- **Alexander Peslyak / Solar Designer** (`<solar@openwall.com>`) - MD4, SHA-2, MD5 implementations
- **Aleksey Kravchenko** (`<rhash.admin@gmail.com>`) - RHash algorithms (SHA-3, Tiger, etc.)
- **Colin Percival** - Scrypt key derivation function
- **Stephan Brumme** (`<create@stephan-brumme.com>`) - CRC32, CRC64, Adler32
- **Steve Reid** (`<steve@edmweb.com>`) - SHA-1 implementation
- **Samuel Neves** (`<sneves@dei.uc.pt>`) - BLAKE2 cryptographic hash
- **Project Nayuki** - Reference cryptographic algorithms and optimizations
- **ARM Limited** - Optimized implementations
- **Yanbo Li** (`dreamfly281@gmail.com`, `goldboar@163.com`) - SM3 cryptographic hash
- **Mark Adler** - CRC and compression algorithms
- **Yann Collet** - xxHash family (XXH32, XXH64, XXH3, XXH128)
- **Nicholas Sherlock** - Adler32 optimizations
