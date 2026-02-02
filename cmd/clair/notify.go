package main

type notifyMsg uint

const (
	_ notifyMsg = iota
	msgReady
	msgReloading
	msgStopping
	msgStatus
	msgSocketAPI
	msgSocketIntrospection
)
