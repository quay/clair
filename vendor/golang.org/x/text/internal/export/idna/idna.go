// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate go run gen.go gen_trieval.go gen_common.go

// http://www.unicode.org/reports/tr46

// Package idna implements IDNA2008 using the compatibility processing
// defined by UTS (Unicode Technical Standard) #46, which defines a standard to
// deal with the transition from IDNA2003.
//
// IDNA2008 (Internationalized Domain Names for Applications), is defined in RFC
// 5890, RFC 5891, RFC 5892, RFC 5893 and RFC 5894.
// UTS #46 is defined in http://www.unicode.org/reports/tr46.
// See http://unicode.org/cldr/utility/idna.jsp for a visualization of the
// differences between these two standards.
package idna // import "golang.org/x/text/internal/export/idna"

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/secure/bidirule"
	"golang.org/x/text/unicode/norm"
)

// ToASCII converts a domain or domain label to its ASCII form. For example,
// ToASCII("bücher.example.com") is "xn--bcher-kva.example.com", and
// ToASCII("golang") is "golang".
func ToASCII(s string) (string, error) {
	return Resolve.process(s, true)
}

// ToUnicode converts a domain or domain label to its Unicode form. For example,
// ToUnicode("xn--bcher-kva.example.com") is "bücher.example.com", and
// ToUnicode("golang") is "golang".
func ToUnicode(s string) (string, error) {
	return NonTransitional.process(s, false)
}

// A Profile defines the configuration of a IDNA mapper.
type Profile struct {
	Transitional    bool
	IgnoreSTD3Rules bool
	IgnoreDNSLength bool
	// ErrHandler      func(error)
}

// ToASCII converts a domain or domain label to its ASCII form. For example,
// ToASCII("bücher.example.com") is "xn--bcher-kva.example.com", and
// ToASCII("golang") is "golang".
func (p *Profile) ToASCII(s string) (string, error) {
	return p.process(s, true)
}

// ToUnicode converts a domain or domain label to its Unicode form. For example,
// ToUnicode("xn--bcher-kva.example.com") is "bücher.example.com", and
// ToUnicode("golang") is "golang".
func (p *Profile) ToUnicode(s string) (string, error) {
	pp := *p
	pp.Transitional = false
	return pp.process(s, false)
}

// String reports a string with a description of the profile for debugging
// purposes. The string format may change with different versions.
func (p *Profile) String() string {
	s := ""
	if p.Transitional {
		s = "Transitional"
	} else {
		s = "NonTraditional"
	}
	if p.IgnoreSTD3Rules {
		s += ":NoSTD3Rules"
	}
	return s
}

var (
	// Resolve is the recommended profile for resolving domain names.
	// The configuration of this profile may change over time.
	Resolve = resolve

	// Display is the recommended profile for displaying domain names.
	// The configuration of this profile may change over time.
	Display = display

	// Transitional defines a profile that implements the Transitional mapping
	// as defined in UTS #46 with no additional constraints.
	Transitional = transitional

	// NonTransitional defines a profile that implements the Transitional
	// mapping as defined in UTS #46 with no additional constraints.
	NonTransitional = nonTransitional

	resolve         = &Profile{Transitional: true}
	display         = &Profile{}
	transitional    = &Profile{Transitional: true}
	nonTransitional = &Profile{}

	// TODO: profiles
	// V2008: strict IDNA2008
	// Register: recommended for approving domain names: nontransitional, but
	// bundle or block deviation characters.
)

// TODO: rethink error strategy

var (
	// errDisallowed indicates a domain name contains a disallowed rune.
	errDisallowed = errors.New("idna: disallowed rune")

	// errEmptyLabel indicates a label was empty.
	errEmptyLabel = errors.New("idna: empty label")
)

// process implements the algorithm described in section 4 of UTS #46,
// see http://www.unicode.org/reports/tr46.
func (p *Profile) process(s string, toASCII bool) (string, error) {
	var (
		b    []byte
		err  error
		k, i int
	)
	for i < len(s) {
		v, sz := trie.lookupString(s[i:])
		start := i
		i += sz
		// Copy bytes not copied so far.
		switch p.simplify(info(v).category()) {
		case valid:
			continue
		case disallowed:
			if err == nil {
				err = errDisallowed
			}
			continue
		case mapped, deviation:
			b = append(b, s[k:start]...)
			b = info(v).appendMapping(b, s[start:i])
		case ignored:
			b = append(b, s[k:start]...)
			// drop the rune
		case unknown:
			b = append(b, s[k:start]...)
			b = append(b, "\ufffd"...)
		}
		k = i
	}
	if k == 0 {
		// No changes so far.
		s = norm.NFC.String(s)
	} else {
		b = append(b, s[k:]...)
		if norm.NFC.QuickSpan(b) != len(b) {
			b = norm.NFC.Bytes(b)
		}
		// TODO: the punycode converters require strings as input.
		s = string(b)
	}
	// Remove leading empty labels
	for ; len(s) > 0 && s[0] == '.'; s = s[1:] {
	}
	if s == "" {
		return "", errors.New("idna: there are no labels")
	}
	labels := labelIter{orig: s}
	for ; !labels.done(); labels.next() {
		label := labels.label()
		if label == "" {
			// Empty labels are not okay. The label iterator skips the last
			// label if it is empty.
			if err == nil {
				err = errEmptyLabel
			}
			continue
		}
		if strings.HasPrefix(label, acePrefix) {
			u, err2 := decode(label[len(acePrefix):])
			if err2 != nil {
				if err == nil {
					err = err2
				}
				// Spec says keep the old label.
				continue
			}
			labels.set(u)
			if err == nil {
				err = p.validateFromPunycode(u)
			}
			if err == nil {
				err = NonTransitional.validate(u)
			}
		} else if err == nil {
			err = p.validate(label)
		}
	}
	if toASCII {
		for labels.reset(); !labels.done(); labels.next() {
			label := labels.label()
			if !ascii(label) {
				a, err2 := encode(acePrefix, label)
				if err == nil {
					err = err2
				}
				label = a
				labels.set(a)
			}
			n := len(label)
			if !p.IgnoreDNSLength && err == nil && (n == 0 || n > 63) {
				err = fmt.Errorf("idna: label with invalid length %d", n)
			}
		}
	}
	s = labels.result()
	if toASCII && !p.IgnoreDNSLength && err == nil {
		// Compute the length of the domain name minus the root label and its dot.
		n := len(s)
		if n > 0 && s[n-1] == '.' {
			n--
		}
		if len(s) < 1 || n > 253 {
			err = fmt.Errorf("idna: doman name with invalid length %d", n)
		}
	}
	return s, err
}

// A labelIter allows iterating over domain name labels.
type labelIter struct {
	orig     string
	slice    []string
	curStart int
	curEnd   int
	i        int
}

func (l *labelIter) reset() {
	l.curStart = 0
	l.curEnd = 0
	l.i = 0
}

func (l *labelIter) done() bool {
	return l.curStart >= len(l.orig)
}

func (l *labelIter) result() string {
	if l.slice != nil {
		return strings.Join(l.slice, ".")
	}
	return l.orig
}

func (l *labelIter) label() string {
	if l.slice != nil {
		return l.slice[l.i]
	}
	p := strings.IndexByte(l.orig[l.curStart:], '.')
	l.curEnd = l.curStart + p
	if p == -1 {
		l.curEnd = len(l.orig)
	}
	return l.orig[l.curStart:l.curEnd]
}

// next sets the value to the next label. It skips the last label if it is empty.
func (l *labelIter) next() {
	l.i++
	if l.slice != nil {
		if l.i >= len(l.slice) || l.i == len(l.slice)-1 && l.slice[l.i] == "" {
			l.curStart = len(l.orig)
		}
	} else {
		l.curStart = l.curEnd + 1
		if l.curStart == len(l.orig)-1 && l.orig[l.curStart] == '.' {
			l.curStart = len(l.orig)
		}
	}
}

func (l *labelIter) set(s string) {
	if l.slice == nil {
		l.slice = strings.Split(l.orig, ".")
	}
	l.slice[l.i] = s
}

// acePrefix is the ASCII Compatible Encoding prefix.
const acePrefix = "xn--"

func (p *Profile) simplify(cat category) category {
	switch cat {
	case disallowedSTD3Mapped:
		if !p.IgnoreSTD3Rules {
			cat = disallowed
		} else {
			cat = mapped
		}
	case disallowedSTD3Valid:
		if !p.IgnoreSTD3Rules {
			cat = disallowed
		} else {
			cat = valid
		}
	case deviation:
		if !p.Transitional {
			cat = valid
		}
	case validNV8, validXV8:
		// TODO: handle V2008
		cat = valid
	}
	return cat
}

func (p *Profile) validateFromPunycode(s string) error {
	if !norm.NFC.IsNormalString(s) {
		return errors.New("idna: punycode is not normalized")
	}
	for i := 0; i < len(s); {
		v, sz := trie.lookupString(s[i:])
		if c := p.simplify(info(v).category()); c != valid && c != deviation {
			return fmt.Errorf("idna: invalid character %+q in expanded punycode", s[i:i+sz])
		}
		i += sz
	}
	return nil
}

const (
	zwnj = "\u200c"
	zwj  = "\u200d"
)

type joinState int8

const (
	stateStart joinState = iota
	stateVirama
	stateBefore
	stateBeforeVirama
	stateAfter
	stateFAIL
)

var joinStates = [][numJoinTypes]joinState{
	stateStart: {
		joiningL:   stateBefore,
		joiningD:   stateBefore,
		joinZWNJ:   stateFAIL,
		joinZWJ:    stateFAIL,
		joinVirama: stateVirama,
	},
	stateVirama: {
		joiningL: stateBefore,
		joiningD: stateBefore,
	},
	stateBefore: {
		joiningL:   stateBefore,
		joiningD:   stateBefore,
		joiningT:   stateBefore,
		joinZWNJ:   stateAfter,
		joinZWJ:    stateFAIL,
		joinVirama: stateBeforeVirama,
	},
	stateBeforeVirama: {
		joiningL: stateBefore,
		joiningD: stateBefore,
		joiningT: stateBefore,
	},
	stateAfter: {
		joiningL:   stateFAIL,
		joiningD:   stateBefore,
		joiningT:   stateAfter,
		joiningR:   stateStart,
		joinZWNJ:   stateFAIL,
		joinZWJ:    stateFAIL,
		joinVirama: stateAfter, // no-op as we can't accept joiners here
	},
	stateFAIL: {
		0:          stateFAIL,
		joiningL:   stateFAIL,
		joiningD:   stateFAIL,
		joiningT:   stateFAIL,
		joiningR:   stateFAIL,
		joinZWNJ:   stateFAIL,
		joinZWJ:    stateFAIL,
		joinVirama: stateFAIL,
	},
}

// validate validates the criteria from Section 4.1. Item 1, 4, and 6 are
// already implicitly satisfied by the overall implementation.
func (p *Profile) validate(s string) error {
	if len(s) > 4 && s[2] == '-' && s[3] == '-' {
		return errors.New("idna: label starts with ??--")
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return errors.New("idna: label may not start or end with '-'")
	}
	// TODO: merge the use of this in the trie.
	v, sz := trie.lookupString(s)
	x := info(v)
	if x.isModifier() {
		return fmt.Errorf("idna: label starts with modifier %U", []rune(s[:sz])[0])
	}
	if !bidirule.ValidString(s) {
		return errors.New("idna: label violates Bidi Rule")
	}
	// Quickly return in the absence of zero-width (non) joiners.
	if strings.Index(s, zwj) == -1 && strings.Index(s, zwnj) == -1 {
		return nil
	}
	st := stateStart
	for i := 0; ; {
		jt := x.joinType()
		if s[i:i+sz] == zwj {
			jt = joinZWJ
		} else if s[i:i+sz] == zwnj {
			jt = joinZWNJ
		}
		st = joinStates[st][jt]
		if x.isViramaModifier() {
			st = joinStates[st][joinVirama]
		}
		if i += sz; i == len(s) {
			break
		}
		v, sz = trie.lookupString(s[i:])
		x = info(v)
	}
	if st == stateFAIL || st == stateAfter {
		return errors.New("idna: label violates Context J rule")
	}
	return nil
}

func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
