// Copyright 2013 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// SHA256 block routine. See sha256block.go for Go equivalent.
//
// The algorithm is detailed in FIPS 180-4:
//
//  http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
//
// Wt = Mt; for 0 <= t <= 15
// Wt = SIGMA1(Wt-2) + SIGMA0(Wt-15) + Wt-16; for 16 <= t <= 63
//
// a = H0
// b = H1
// c = H2
// d = H3
// e = H4
// f = H5
// g = H6
// h = H7
//
// for t = 0 to 63 {
//    T1 = h + BIGSIGMA1(e) + Ch(e,f,g) + Kt + Wt
//    T2 = BIGSIGMA0(a) + Maj(a,b,c)
//    h = g
//    g = f
//    f = e
//    e = d + T1
//    d = c
//    c = b
//    b = a
//    a = T1 + T2
// }
//
// H0 = a + H0
// H1 = b + H1
// H2 = c + H2
// H3 = d + H3
// H4 = e + H4
// H5 = f + H5
// H6 = g + H6
// H7 = h + H7

// Wt = Mt; for 0 <= t <= 15
#define MSGSCHEDULE0(index) \
	MOVL	(index*4)(SI), AX; \
	BSWAPL	AX; \
	MOVL	AX, (index*4)(BP)

// Wt = SIGMA1(Wt-2) + Wt-7 + SIGMA0(Wt-15) + Wt-16; for 16 <= t <= 63
//   SIGMA0(x) = ROTR(7,x) XOR ROTR(18,x) XOR SHR(3,x)
//   SIGMA1(x) = ROTR(17,x) XOR ROTR(19,x) XOR SHR(10,x)
#define MSGSCHEDULE1(index) \
	MOVL	((index-2)*4)(BP), AX; \
	MOVL	AX, CX; \
	RORL	$17, AX; \
	MOVL	CX, DX; \
	RORL	$19, CX; \
	SHRL	$10, DX; \
	MOVL	((index-15)*4)(BP), BX; \
	XORL	CX, AX; \
	MOVL	BX, CX; \
	XORL	DX, AX; \
	RORL	$7, BX; \
	MOVL	CX, DX; \
	SHRL	$3, DX; \
	RORL	$18, CX; \
	ADDL	((index-7)*4)(BP), AX; \
	XORL	CX, BX; \
	XORL	DX, BX; \
	ADDL	((index-16)*4)(BP), BX; \
	ADDL	BX, AX; \
	MOVL	AX, ((index)*4)(BP)

// Calculate T1 in AX - uses AX, CX and DX registers.
// h is also used as an accumulator. Wt is passed in AX.
//   T1 = h + BIGSIGMA1(e) + Ch(e, f, g) + Kt + Wt
//     BIGSIGMA1(x) = ROTR(6,x) XOR ROTR(11,x) XOR ROTR(25,x)
//     Ch(x, y, z) = (x AND y) XOR (NOT x AND z)
#define SHA256T1(const, e, f, g, h) \
	ADDL	AX, h; \
	MOVL	e, AX; \
	ADDL	$const, h; \
	MOVL	e, CX; \
	RORL	$6, AX; \
	MOVL	e, DX; \
	RORL	$11, CX; \
	XORL	CX, AX; \
	MOVL	e, CX; \
	RORL	$25, DX; \
	ANDL	f, CX; \
	XORL	AX, DX; \
	MOVL	e, AX; \
	NOTL	AX; \
	ADDL	DX, h; \
	ANDL	g, AX; \
	XORL	CX, AX; \
	ADDL	h, AX

// Calculate T2 in BX - uses BX, CX, DX and DI registers.
//   T2 = BIGSIGMA0(a) + Maj(a, b, c)
//     BIGSIGMA0(x) = ROTR(2,x) XOR ROTR(13,x) XOR ROTR(22,x)
//     Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
#define SHA256T2(a, b, c) \
	MOVL	a, DI; \
	MOVL	c, BX; \
	RORL	$2, DI; \
	MOVL	a, DX; \
	ANDL	b, BX; \
	RORL	$13, DX; \
	MOVL	a, CX; \
	ANDL	c, CX; \
	XORL	DX, DI; \
	XORL	CX, BX; \
	MOVL	a, DX; \
	MOVL	b, CX; \
	RORL	$22, DX; \
	ANDL	a, CX; \
	XORL	CX, BX; \
	XORL	DX, DI; \
	ADDL	DI, BX

// Calculate T1 and T2, then e = d + T1 and a = T1 + T2.
// The values for e and a are stored in d and h, ready for rotation.
#define SHA256ROUND(index, const, a, b, c, d, e, f, g, h) \
	SHA256T1(const, e, f, g, h); \
	SHA256T2(a, b, c); \
	MOVL	BX, h; \
	ADDL	AX, d; \
	ADDL	AX, h

#define SHA256ROUND0(index, const, a, b, c, d, e, f, g, h) \
	MSGSCHEDULE0(index); \
	SHA256ROUND(index, const, a, b, c, d, e, f, g, h)

#define SHA256ROUND1(index, const, a, b, c, d, e, f, g, h) \
	MSGSCHEDULE1(index); \
	SHA256ROUND(index, const, a, b, c, d, e, f, g, h)

TEXT ·block(SB),0,$264-32
	MOVQ	p_base+8(FP), SI
	MOVQ	p_len+16(FP), DX
	SHRQ	$6, DX
	SHLQ	$6, DX

	LEAQ	(SI)(DX*1), DI
	MOVQ	DI, 256(SP)
	CMPQ	SI, DI
	JEQ	end

	MOVQ	dig+0(FP), BP
	MOVL	(0*4)(BP), R8		// a = H0
	MOVL	(1*4)(BP), R9		// b = H1
	MOVL	(2*4)(BP), R10		// c = H2
	MOVL	(3*4)(BP), R11		// d = H3
	MOVL	(4*4)(BP), R12		// e = H4
	MOVL	(5*4)(BP), R13		// f = H5
	MOVL	(6*4)(BP), R14		// g = H6
	MOVL	(7*4)(BP), R15		// h = H7

loop:
	MOVQ	SP, BP			// message schedule

	SHA256ROUND0(0, 0x428a2f98, R8, R9, R10, R11, R12, R13, R14, R15)
	SHA256ROUND0(1, 0x71374491, R15, R8, R9, R10, R11, R12, R13, R14)
	SHA256ROUND0(2, 0xb5c0fbcf, R14, R15, R8, R9, R10, R11, R12, R13)
	SHA256ROUND0(3, 0xe9b5dba5, R13, R14, R15, R8, R9, R10, R11, R12)
	SHA256ROUND0(4, 0x3956c25b, R12, R13, R14, R15, R8, R9, R10, R11)
	SHA256ROUND0(5, 0x59f111f1, R11, R12, R13, R14, R15, R8, R9, R10)
	SHA256ROUND0(6, 0x923f82a4, R10, R11, R12, R13, R14, R15, R8, R9)
	SHA256ROUND0(7, 0xab1c5ed5, R9, R10, R11, R12, R13, R14, R15, R8)
	SHA256ROUND0(8, 0xd807aa98, R8, R9, R10, R11, R12, R13, R14, R15)
	SHA256ROUND0(9, 0x12835b01, R15, R8, R9, R10, R11, R12, R13, R14)
	SHA256ROUND0(10, 0x243185be, R14, R15, R8, R9, R10, R11, R12, R13)
	SHA256ROUND0(11, 0x550c7dc3, R13, R14, R15, R8, R9, R10, R11, R12)
	SHA256ROUND0(12, 0x72be5d74, R12, R13, R14, R15, R8, R9, R10, R11)
	SHA256ROUND0(13, 0x80deb1fe, R11, R12, R13, R14, R15, R8, R9, R10)
	SHA256ROUND0(14, 0x9bdc06a7, R10, R11, R12, R13, R14, R15, R8, R9)
	SHA256ROUND0(15, 0xc19bf174, R9, R10, R11, R12, R13, R14, R15, R8)

	SHA256ROUND1(16, 0xe49b69c1, R8, R9, R10, R11, R12, R13, R14, R15)
	SHA256ROUND1(17, 0xefbe4786, R15, R8, R9, R10, R11, R12, R13, R14)
	SHA256ROUND1(18, 0x0fc19dc6, R14, R15, R8, R9, R10, R11, R12, R13)
	SHA256ROUND1(19, 0x240ca1cc, R13, R14, R15, R8, R9, R10, R11, R12)
	SHA256ROUND1(20, 0x2de92c6f, R12, R13, R14, R15, R8, R9, R10, R11)
	SHA256ROUND1(21, 0x4a7484aa, R11, R12, R13, R14, R15, R8, R9, R10)
	SHA256ROUND1(22, 0x5cb0a9dc, R10, R11, R12, R13, R14, R15, R8, R9)
	SHA256ROUND1(23, 0x76f988da, R9, R10, R11, R12, R13, R14, R15, R8)
	SHA256ROUND1(24, 0x983e5152, R8, R9, R10, R11, R12, R13, R14, R15)
	SHA256ROUND1(25, 0xa831c66d, R15, R8, R9, R10, R11, R12, R13, R14)
	SHA256ROUND1(26, 0xb00327c8, R14, R15, R8, R9, R10, R11, R12, R13)
	SHA256ROUND1(27, 0xbf597fc7, R13, R14, R15, R8, R9, R10, R11, R12)
	SHA256ROUND1(28, 0xc6e00bf3, R12, R13, R14, R15, R8, R9, R10, R11)
	SHA256ROUND1(29, 0xd5a79147, R11, R12, R13, R14, R15, R8, R9, R10)
	SHA256ROUND1(30, 0x06ca6351, R10, R11, R12, R13, R14, R15, R8, R9)
	SHA256ROUND1(31, 0x14292967, R9, R10, R11, R12, R13, R14, R15, R8)
	SHA256ROUND1(32, 0x27b70a85, R8, R9, R10, R11, R12, R13, R14, R15)
	SHA256ROUND1(33, 0x2e1b2138, R15, R8, R9, R10, R11, R12, R13, R14)
	SHA256ROUND1(34, 0x4d2c6dfc, R14, R15, R8, R9, R10, R11, R12, R13)
	SHA256ROUND1(35, 0x53380d13, R13, R14, R15, R8, R9, R10, R11, R12)
	SHA256ROUND1(36, 0x650a7354, R12, R13, R14, R15, R8, R9, R10, R11)
	SHA256ROUND1(37, 0x766a0abb, R11, R12, R13, R14, R15, R8, R9, R10)
	SHA256ROUND1(38, 0x81c2c92e, R10, R11, R12, R13, R14, R15, R8, R9)
	SHA256ROUND1(39, 0x92722c85, R9, R10, R11, R12, R13, R14, R15, R8)
	SHA256ROUND1(40, 0xa2bfe8a1, R8, R9, R10, R11, R12, R13, R14, R15)
	SHA256ROUND1(41, 0xa81a664b, R15, R8, R9, R10, R11, R12, R13, R14)
	SHA256ROUND1(42, 0xc24b8b70, R14, R15, R8, R9, R10, R11, R12, R13)
	SHA256ROUND1(43, 0xc76c51a3, R13, R14, R15, R8, R9, R10, R11, R12)
	SHA256ROUND1(44, 0xd192e819, R12, R13, R14, R15, R8, R9, R10, R11)
	SHA256ROUND1(45, 0xd6990624, R11, R12, R13, R14, R15, R8, R9, R10)
	SHA256ROUND1(46, 0xf40e3585, R10, R11, R12, R13, R14, R15, R8, R9)
	SHA256ROUND1(47, 0x106aa070, R9, R10, R11, R12, R13, R14, R15, R8)
	SHA256ROUND1(48, 0x19a4c116, R8, R9, R10, R11, R12, R13, R14, R15)
	SHA256ROUND1(49, 0x1e376c08, R15, R8, R9, R10, R11, R12, R13, R14)
	SHA256ROUND1(50, 0x2748774c, R14, R15, R8, R9, R10, R11, R12, R13)
	SHA256ROUND1(51, 0x34b0bcb5, R13, R14, R15, R8, R9, R10, R11, R12)
	SHA256ROUND1(52, 0x391c0cb3, R12, R13, R14, R15, R8, R9, R10, R11)
	SHA256ROUND1(53, 0x4ed8aa4a, R11, R12, R13, R14, R15, R8, R9, R10)
	SHA256ROUND1(54, 0x5b9cca4f, R10, R11, R12, R13, R14, R15, R8, R9)
	SHA256ROUND1(55, 0x682e6ff3, R9, R10, R11, R12, R13, R14, R15, R8)
	SHA256ROUND1(56, 0x748f82ee, R8, R9, R10, R11, R12, R13, R14, R15)
	SHA256ROUND1(57, 0x78a5636f, R15, R8, R9, R10, R11, R12, R13, R14)
	SHA256ROUND1(58, 0x84c87814, R14, R15, R8, R9, R10, R11, R12, R13)
	SHA256ROUND1(59, 0x8cc70208, R13, R14, R15, R8, R9, R10, R11, R12)
	SHA256ROUND1(60, 0x90befffa, R12, R13, R14, R15, R8, R9, R10, R11)
	SHA256ROUND1(61, 0xa4506ceb, R11, R12, R13, R14, R15, R8, R9, R10)
	SHA256ROUND1(62, 0xbef9a3f7, R10, R11, R12, R13, R14, R15, R8, R9)
	SHA256ROUND1(63, 0xc67178f2, R9, R10, R11, R12, R13, R14, R15, R8)

	MOVQ	dig+0(FP), BP
	ADDL	(0*4)(BP), R8	// H0 = a + H0
	MOVL	R8, (0*4)(BP)
	ADDL	(1*4)(BP), R9	// H1 = b + H1
	MOVL	R9, (1*4)(BP)
	ADDL	(2*4)(BP), R10	// H2 = c + H2
	MOVL	R10, (2*4)(BP)
	ADDL	(3*4)(BP), R11	// H3 = d + H3
	MOVL	R11, (3*4)(BP)
	ADDL	(4*4)(BP), R12	// H4 = e + H4
	MOVL	R12, (4*4)(BP)
	ADDL	(5*4)(BP), R13	// H5 = f + H5
	MOVL	R13, (5*4)(BP)
	ADDL	(6*4)(BP), R14	// H6 = g + H6
	MOVL	R14, (6*4)(BP)
	ADDL	(7*4)(BP), R15	// H7 = h + H7
	MOVL	R15, (7*4)(BP)

	ADDQ	$64, SI
	CMPQ	SI, 256(SP)
	JB	loop

end:
	RET
