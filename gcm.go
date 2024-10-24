// Copyright (c) 2009 The Go Authors. All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:

//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
package uncheckedgcm

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"unsafe"
)

const (
	gcmNonceSize = 16
	gcmBlockSize = 16
	gcmTagSize   = 16
)

var errOpen = errors.New("gcm: message authentication failed")

var gcmReductionTable = []uint16{
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
}

type gcmFieldElement struct {
	low, high uint64
}

type gcm struct {
	cipher       cipher.Block
	tagMask      [gcmBlockSize]byte
	counter      [gcmBlockSize]byte
	extraMask    []byte
	ghash        gcmFieldElement
	productTable [16]gcmFieldElement
}

type gcmEncrypter struct {
	*gcm
	plaintextNb      uint64
	additionalDataNb uint64
}

type gcmDecrypter struct {
	*gcm
	ciphertextNb     uint64
	additionalDataNb uint64
}

func anyOverlap(x, y []byte) bool {
	return len(x) > 0 && len(y) > 0 &&
		uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}

func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	return anyOverlap(x, y)
}

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

func reverseBits(i int) int {
	i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
	i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
	return i
}

func gcmInc32(counterBlock *[16]byte) {
	ctr := counterBlock[len(counterBlock)-4:]
	binary.BigEndian.PutUint32(ctr, binary.BigEndian.Uint32(ctr)+1)
}

func gcmAdd(x, y *gcmFieldElement) gcmFieldElement {
	return gcmFieldElement{x.low ^ y.low, x.high ^ y.high}
}

func gcmDouble(x *gcmFieldElement) (double gcmFieldElement) {
	msbSet := x.high&1 == 1

	double.high = x.high >> 1
	double.high |= x.low << 63
	double.low = x.low >> 1

	if msbSet {
		double.low ^= 0xe100000000000000
	}

	return
}

func newGCMEncrypter(cipher cipher.Block, nonce, additionalData []byte) *gcmEncrypter {
	if len(nonce) != gcmNonceSize {
		panic("incorrect nonce length given to GCM")
	}

	var key [gcmBlockSize]byte
	cipher.Encrypt(key[:], key[:])

	g := &gcmEncrypter{
		gcm: &gcm{
			cipher: cipher,
		},
		plaintextNb:      0,
		additionalDataNb: uint64(len(additionalData)),
	}

	x := gcmFieldElement{
		binary.BigEndian.Uint64(key[:8]),
		binary.BigEndian.Uint64(key[8:]),
	}
	g.productTable[reverseBits(1)] = x

	for i := 2; i < 16; i += 2 {
		g.productTable[reverseBits(i)] = gcmDouble(&g.productTable[reverseBits(i/2)])
		g.productTable[reverseBits(i+1)] = gcmAdd(&g.productTable[reverseBits(i)], &x)
	}

	g.update(&g.ghash, additionalData)

	g.deriveCounter(nonce)
	g.cipher.Encrypt(g.tagMask[:], g.counter[:])
	gcmInc32(&g.counter)

	return g
}

func newGCMDecrypter(cipher cipher.Block, nonce, additionalData []byte) *gcmDecrypter {
	if len(nonce) != gcmNonceSize {
		panic("gcm: incorrect nonce length given to GCM")
	}

	var key [gcmBlockSize]byte
	cipher.Encrypt(key[:], key[:])

	g := &gcmDecrypter{
		gcm: &gcm{
			cipher: cipher,
		},
		ciphertextNb:     0,
		additionalDataNb: uint64(len(additionalData)),
	}

	x := gcmFieldElement{
		binary.BigEndian.Uint64(key[:8]),
		binary.BigEndian.Uint64(key[8:]),
	}
	g.productTable[reverseBits(1)] = x

	for i := 2; i < 16; i += 2 {
		g.productTable[reverseBits(i)] = gcmDouble(&g.productTable[reverseBits(i/2)])
		g.productTable[reverseBits(i+1)] = gcmAdd(&g.productTable[reverseBits(i)], &x)
	}

	g.update(&g.ghash, additionalData)

	g.deriveCounter(nonce)
	g.cipher.Encrypt(g.tagMask[:], g.counter[:])
	gcmInc32(&g.counter)

	return g
}

// Encrypt encrypts the plaintext and returns the resulting ciphertext.
func (g *gcmEncrypter) Encrypt(dst, plaintext []byte) []byte {
	ret, out := sliceForAppend(dst, len(plaintext))
	if inexactOverlap(out, plaintext) {
		panic("gcm: invalid buffer overlap")
	}

	g.update(&g.ghash, plaintext)
	g.plaintextNb += uint64(len(plaintext))

	g.counterCrypt(out, plaintext, &g.counter)

	return ret
}

// Tag returns the GCM tag for the plaintext processed so far.
func (g *gcmEncrypter) Tag() [gcmTagSize]byte {
	var tag [gcmTagSize]byte

	g.ghash.low ^= g.additionalDataNb * 8
	g.ghash.high ^= g.plaintextNb * 8
	g.mul(&g.ghash)

	binary.BigEndian.PutUint64(tag[:], g.ghash.low)
	binary.BigEndian.PutUint64(tag[8:], g.ghash.high)

	subtle.XORBytes(tag[:], tag[:], g.tagMask[:])
	return tag
}

// Verify returns nil if the tag matches the correct GCM tag for the ciphertext processed so far.
func (g *gcmDecrypter) Verify(tag []byte) error {
	if len(tag) != gcmTagSize {
		return errOpen
	}

	expected := g.Tag()
	if subtle.ConstantTimeCompare(expected[:], tag) != 1 {
		return errOpen
	}

	return nil
}

// Decrypt decrypts the ciphertext and returns the resulting plaintext.
func (g *gcmDecrypter) Decrypt(dst, ciphertext []byte) ([]byte, error) {
	ret, out := sliceForAppend(dst, len(ciphertext))
	if inexactOverlap(out, ciphertext) {
		panic("gcm: invalid buffer overlap")
	}

	g.update(&g.ghash, ciphertext)
	g.ciphertextNb += uint64(len(ciphertext))

	g.counterCrypt(out, ciphertext, &g.counter)

	return ret, nil
}

// Tag returns the GCM tag for the ciphertext processed so far.
func (g *gcmDecrypter) Tag() [gcmTagSize]byte {
	var tag [gcmTagSize]byte

	g.ghash.low ^= g.additionalDataNb * 8
	g.ghash.high ^= g.ciphertextNb * 8
	g.mul(&g.ghash)

	binary.BigEndian.PutUint64(tag[:], g.ghash.low)
	binary.BigEndian.PutUint64(tag[8:], g.ghash.high)

	subtle.XORBytes(tag[:], tag[:], g.tagMask[:])
	return tag
}

func (g *gcm) mul(y *gcmFieldElement) {
	var z gcmFieldElement

	for i := 0; i < 2; i++ {
		word := y.high
		if i == 1 {
			word = y.low
		}

		// Multiplication works by multiplying z by 16 and adding in
		// one of the precomputed multiples of H.
		for j := 0; j < 64; j += 4 {
			msw := z.high & 0xf
			z.high >>= 4
			z.high |= z.low << 60
			z.low >>= 4
			z.low ^= uint64(gcmReductionTable[msw]) << 48

			// the values in |table| are ordered for
			// little-endian bit positions. See the comment
			// in NewGCMWithNonceSize.
			t := &g.productTable[word&0xf]

			z.low ^= t.low
			z.high ^= t.high
			word >>= 4
		}
	}

	*y = z
}

func (g *gcm) updateBlocks(y *gcmFieldElement, blocks []byte) {
	for len(blocks) > 0 {
		y.low ^= binary.BigEndian.Uint64(blocks)
		y.high ^= binary.BigEndian.Uint64(blocks[8:])
		g.mul(y)
		blocks = blocks[gcmBlockSize:]
	}
}

func (g *gcm) update(y *gcmFieldElement, data []byte) {
	fullBlocks := (len(data) >> 4) << 4
	g.updateBlocks(y, data[:fullBlocks])

	if len(data) != fullBlocks {
		var partialBlock [gcmBlockSize]byte
		copy(partialBlock[:], data[fullBlocks:])
		g.updateBlocks(y, partialBlock[:])
	}
}

func (g *gcm) deriveCounter(nonce []byte) {
	var y gcmFieldElement
	g.update(&y, nonce[:])
	y.high ^= uint64(len(nonce)) * 8
	g.mul(&y)
	binary.BigEndian.PutUint64(g.counter[:8], y.low)
	binary.BigEndian.PutUint64(g.counter[8:], y.high)
}

func (g *gcm) counterCrypt(out, in []byte, counter *[gcmBlockSize]byte) {
	var mask [gcmBlockSize]byte

	if len(g.extraMask) > 0 {
		n := subtle.XORBytes(out, in, g.extraMask)
		out = out[n:]
		in = in[n:]
		g.extraMask = g.extraMask[n:]
	}

	for len(in) > 0 {
		g.cipher.Encrypt(mask[:], counter[:])
		gcmInc32(counter)

		n := subtle.XORBytes(out, in, mask[:])
		out = out[n:]
		in = in[n:]
		g.extraMask = mask[n:]
	}
}
