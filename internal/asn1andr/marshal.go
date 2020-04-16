// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn1andr

import (
	"encoding/asn1"
	"math/big"
)

var (
	byte00Encoder encoder = byteEncoder(0x00)
	byteFFEncoder encoder = byteEncoder(0xff)
)

// encoder represents an ASN.1 element that is waiting to be marshaled.
type encoder interface {
	// Len returns the number of bytes needed to marshal this element.
	Len() int
	// Encode encodes this element by writing Len() bytes to dst.
	Encode(dst []byte)
}

type byteEncoder byte

func (c byteEncoder) Len() int {
	return 1
}

func (c byteEncoder) Encode(dst []byte) {
	dst[0] = byte(c)
}

type bytesEncoder []byte

func (b bytesEncoder) Len() int {
	return len(b)
}

func (b bytesEncoder) Encode(dst []byte) {
	if copy(dst, b) != len(b) {
		panic("internal error")
	}
}

type multiEncoder []encoder

func (m multiEncoder) Len() int {
	var size int
	for _, e := range m {
		size += e.Len()
	}
	return size
}

func (m multiEncoder) Encode(dst []byte) {
	var off int
	for _, e := range m {
		e.Encode(dst[off:])
		off += e.Len()
	}
}

func makeBigInt(n *big.Int) (encoder, error) {
	if n == nil {
		return nil, asn1.StructuralError{"empty integer"}
	}

	if n.Sign() < 0 {
		// A negative number has to be converted to two's-complement
		// form. So we'll invert and subtract 1. If the
		// most-significant-bit isn't set then we'll need to pad the
		// beginning with 0xff in order to keep the number negative.
		nMinus1 := new(big.Int).Neg(n)
		nMinus1.Sub(nMinus1, bigOne)
		bytes := nMinus1.Bytes()
		for i := range bytes {
			bytes[i] ^= 0xff
		}
		if len(bytes) == 0 || bytes[0]&0x80 == 0 {
			return multiEncoder([]encoder{byteFFEncoder, bytesEncoder(bytes)}), nil
		}
		return bytesEncoder(bytes), nil
	} else if n.Sign() == 0 {
		// Zero is written as a single 0 zero rather than no bytes.
		return byte00Encoder, nil
	} else {
		bytes := n.Bytes()
		if len(bytes) > 0 && bytes[0]&0x80 != 0 {
			// We'll have to pad this with 0x00 in order to stop it
			// looking like a negative number.
			return multiEncoder([]encoder{byte00Encoder, bytesEncoder(bytes)}), nil
		}
		return bytesEncoder(bytes), nil
	}
}
