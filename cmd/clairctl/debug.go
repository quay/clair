package main

import (
	"io/ioutil"
	"log"
)

var debug = log.New(ioutil.Discard, "debug: ", log.LstdFlags)
