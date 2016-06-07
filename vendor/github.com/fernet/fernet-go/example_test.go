package fernet_test

import (
	"fmt"
	"time"

	"github.com/fernet/fernet-go"
)

func Example() {
	k := fernet.MustDecodeKeys("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=")
	tok, err := fernet.EncryptAndSign([]byte("hello"), k[0])
	if err != nil {
		panic(err)
	}
	msg := fernet.VerifyAndDecrypt(tok, 60*time.Second, k)
	fmt.Println(string(msg))
	// Output:
	// hello
}
