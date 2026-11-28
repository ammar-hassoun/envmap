package main

// XXH64, the checksum the engine uses for pages in transit and for the
// disks of a powered-off machine. No build tag: the powered-off copy and
// its tests run wherever Go does.

import (
	"encoding/binary"
	"math/bits"
)

const (
	p1 uint64 = 0x9E3779B185EBCA87
	p2 uint64 = 0xC2B2AE3D27D4EB4F
	p3 uint64 = 0x165667B19E3779F9
	p4 uint64 = 0x85EBCA77C2B2AE63
	p5 uint64 = 0x27D4EB2F165667C5
)

func xxround(acc, in uint64) uint64 { return bits.RotateLeft64(acc+in*p2, 31) * p1 }

func xxmerge(acc, v uint64) uint64 { return (acc^xxround(0, v))*p1 + p4 }

// xxh64 is XXH64 for inputs whose length is a multiple of 32 (pages).
func xxh64(b []byte, seed uint64) uint64 {
	le := binary.LittleEndian
	n := uint64(len(b))
	var h uint64
	if n >= 32 {
		v1, v2, v3, v4 := seed+p1+p2, seed+p2, seed, seed-p1
		for len(b) >= 32 {
			v1 = xxround(v1, le.Uint64(b[0:]))
			v2 = xxround(v2, le.Uint64(b[8:]))
			v3 = xxround(v3, le.Uint64(b[16:]))
			v4 = xxround(v4, le.Uint64(b[24:]))
			b = b[32:]
		}
		h = bits.RotateLeft64(v1, 1) + bits.RotateLeft64(v2, 7) + bits.RotateLeft64(v3, 12) + bits.RotateLeft64(v4, 18)
		h = xxmerge(h, v1)
		h = xxmerge(h, v2)
		h = xxmerge(h, v3)
		h = xxmerge(h, v4)
	} else {
		h = seed + p5
	}
	h += n
	for len(b) >= 8 {
		h ^= xxround(0, le.Uint64(b))
		h = bits.RotateLeft64(h, 27)*p1 + p4
		b = b[8:]
	}
	for len(b) >= 4 {
		h ^= uint64(le.Uint32(b)) * p1
		h = bits.RotateLeft64(h, 23)*p2 + p3
		b = b[4:]
	}
	for _, c := range b {
		h ^= uint64(c) * p5
		h = bits.RotateLeft64(h, 11) * p1
	}
	h ^= h >> 33
	h *= p2
	h ^= h >> 29
	h *= p3
	h ^= h >> 32
	return h
}
