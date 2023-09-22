package main

import (
	"flag"
	"log"
	"os"

	"github.com/webee/socks5"
)

var (
	logger *log.Logger
	// arguments
	addr      string
	user      string
	pass      string
	relay_sep string
)

func init() {
	logger = log.New(os.Stdout, "", log.LstdFlags)
	flag.StringVar(&addr, "addr", ":1080", "address to listen")
	flag.StringVar(&user, "user", "", "username")
	flag.StringVar(&pass, "pass", "", "password")
	flag.StringVar(&relay_sep, "relay-sep", "__r_", "relay info separator")
}

func main() {
	flag.Parse()

	conf := &socks5.Config{Logger: logger}
	if user != "" || relay_sep != "" {
		conf.Credentials = socks5.StaticCredentials{user: pass}
		conf.CredentialSep = relay_sep
	}

	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	logger.Printf("starting socks5 proxy on %s\n", addr)
	if err := server.ListenAndServe("tcp", addr); err != nil {
		panic(err)
	}
}
