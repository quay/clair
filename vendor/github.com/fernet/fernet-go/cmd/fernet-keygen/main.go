package main

import (
	"fmt"
	"log"

	"github.com/fernet/fernet-go"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("fernet: ")

	var key fernet.Key
	if err := key.Generate(); err != nil {
		log.Fatal(err)
	}
	fmt.Println(key.Encode())
}
