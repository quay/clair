package fernet

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"
)

type test struct {
	Secret string
	Src    string
	IV     [aes.BlockSize]byte
	Now    time.Time
	TTLSec int `json:"ttl_sec"`
	Token  string
	Desc   string
}

func mustLoadTests(path string) []test {
	var ts []test
	if f, err := os.Open(path); err != nil {
		panic(err)
	} else if err = json.NewDecoder(f).Decode(&ts); err != nil {
		panic(err)
	}
	return ts
}

func TestGenerate(t *testing.T) {
	for _, tok := range mustLoadTests("generate.json") {
		k := MustDecodeKeys(tok.Secret)
		g := make([]byte, encodedLen(len(tok.Src)))
		n := gen(g, []byte(tok.Src), tok.IV[:], tok.Now, k[0])
		if n != len(g) {
			t.Errorf("want %v, got %v", len(g), n)
		}
		s := base64.URLEncoding.EncodeToString(g)
		if s != tok.Token {
			t.Errorf("want %q, got %q", tok.Token, g)
			t.Log("want")
			dumpTok(t, tok.Token, len(tok.Token))
			t.Log("got")
			dumpTok(t, s, n)
		}
	}
}

func TestVerifyOk(t *testing.T) {
	for i, tok := range mustLoadTests("verify.json") {
		t.Logf("test %d %s", i, tok.Desc)
		k := MustDecodeKeys(tok.Secret)
		t.Log("tok")
		dumpTok(t, tok.Token, len(tok.Token))
		ttl := time.Duration(tok.TTLSec) * time.Second
		b := mustBase64DecodeString(tok.Token)
		g := verify(nil, b, ttl, tok.Now, k[0])
		if string(g) != tok.Src {
			t.Errorf("got %#v != exp %#v", string(g), tok.Src)
		}
	}
}

func TestVerifyBad(t *testing.T) {
	for i, tok := range mustLoadTests("invalid.json") {
		if tok.Desc == "invalid base64" {
			continue
		}
		t.Logf("test %d %s", i, tok.Desc)
		t.Log(tok.Token)
		b, err := base64.URLEncoding.DecodeString(tok.Token)
		if err != nil {
			panic(err)
		}
		k := MustDecodeKeys(tok.Secret)
		ttl := time.Duration(tok.TTLSec) * time.Second
		if g := verify(nil, b, ttl, tok.Now, k[0]); g != nil {
			t.Errorf("got %#v", string(g))
		}
	}
}

func TestVerifyBadBase64(t *testing.T) {
	for i, tok := range mustLoadTests("invalid.json") {
		if tok.Desc != "invalid base64" {
			continue
		}
		t.Logf("test %d %s", i, tok.Desc)
		t.Log(tok.Token)
		k := MustDecodeKeys(tok.Secret)
		ttl := time.Duration(tok.TTLSec) * time.Second
		if g := VerifyAndDecrypt([]byte(tok.Token), ttl, k); g != nil {
			t.Errorf("got %#v", string(g))
		}
	}
}

func BenchmarkGenerate(b *testing.B) {
	k := new(Key)
	k.Generate()
	msg := []byte("hello")
	g := make([]byte, encodedLen(len(msg)))
	for i := 0; i < b.N; i++ {
		iv := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			b.Fatal(err)
		}
		gen(g, msg, iv, time.Now(), k)
		//k.EncryptAndSign([]byte("hello"))
	}
}

func BenchmarkVerifyOk(b *testing.B) {
	t := mustLoadTests("verify.json")[0]
	k := MustDecodeKeys(t.Secret)
	ttl := time.Duration(t.TTLSec) * time.Second
	tok := mustBase64DecodeString(t.Token)
	for i := 0; i < b.N; i++ {
		verify(nil, tok, ttl, t.Now, k[0])
	}
}

func BenchmarkVerifyBad(b *testing.B) {
	t := mustLoadTests("invalid.json")[0]
	k := MustDecodeKeys(t.Secret)
	ttl := time.Duration(t.TTLSec) * time.Second
	tok := mustBase64DecodeString(t.Token)
	for i := 0; i < b.N; i++ {
		verify(nil, tok, ttl, t.Now, k[0])
	}
}

func dumpTok(t *testing.T, s string, n int) {
	tok := mustBase64DecodeString(s)
	dumpField(t, tok, 0, 1)
	dumpField(t, tok, 1, 1+8)
	dumpField(t, tok, 1+8, 1+8+16)
	dumpField(t, tok, 1+8+16, n-32)
	dumpField(t, tok, n-32, n)
}

func dumpField(t *testing.T, b []byte, n, e int) {
	if len(b) < e {
		e = len(b)
	}
	t.Log(b[n:e])
}

func mustBase64DecodeString(s string) []byte {
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
