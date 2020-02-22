package main

import "log"

func main() {
	server, _ := NewSSHServer(":2222")
	log.Fatal(server.ListenAndServe())
}
