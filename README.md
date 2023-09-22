# go-socks5 [![Build Status](https://travis-ci.org/armon/go-socks5.png)](https://travis-ci.org/armon/go-socks5)

Provides the `socks5` package that implements a [SOCKS5 server](http://en.wikipedia.org/wiki/SOCKS).
SOCKS (Secure Sockets) is used to route traffic between a client and server through
an intermediate proxy layer. This can be used to bypass firewalls or NATs.

# socks5-proxy command

usage:

```
// listen on 1080 for all interfaces
# socks5-proxy --addr=:1080 --user=user --pass=pass [--relay-sep='__r_']
```

```
// test use proxy
# curl -x 'socks5://user:pass@<ip>:<port>' httpbin.org/ip
// test use proxy with relay
# curl -x 'socks5://user__r_<ru>__r_<rp>__r_<rh>__r_<rp>:pass@<ip>:<port>' httpbin.org/ip
```

# Feature

The package has the following features:

- "No Auth" mode
- User/Password authentication
- Support for the CONNECT command
- Rules to do granular filtering of commands
- Custom DNS resolution
- Unit tests

# TODO

The package still needs the following:

- Support for the BIND command
- Support for the ASSOCIATE command

# Example

Below is a simple example of usage

```go
// Create a SOCKS5 server
conf := &socks5.Config{}
server, err := socks5.New(conf)
if err != nil {
  panic(err)
}

// Create SOCKS5 proxy on localhost port 8000
if err := server.ListenAndServe("tcp", "127.0.0.1:8000"); err != nil {
  panic(err)
}
```
