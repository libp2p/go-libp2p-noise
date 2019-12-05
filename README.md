# go-libp2p-noise

[![](https://img.shields.io/badge/made%20by-ETHBerlinZwei-blue.svg?style=flat-square)](https://ethberlinzwei.com)
[![](https://img.shields.io/badge/project-libp2p-yellow.svg?style=flat-square)](https://libp2p.io/)
[![](https://img.shields.io/badge/freenode-%23libp2p-yellow.svg?style=flat-square)](http://webchat.freenode.net/?channels=%23libp2p)
[![Discourse posts](https://img.shields.io/discourse/https/discuss.libp2p.io/posts.svg)](https://discuss.libp2p.io)
[![GoDoc](https://godoc.org/github.com/ChainSafe/go-libp2p-noise?status.svg)](https://godoc.org/github.com/ChainSafe/go-libp2p-noise)
[![Build Status](https://travis-ci.org/ChainSafe/go-libp2p-noise.svg?branch=master)](https://travis-ci.org/ChainSafe/go-libp2p-noise)

> go-libp2p's noise encrypted transport

`go-libp2p-noise` is a component of the [libp2p project](https://libp2p.io), a
modular networking stack for developing peer-to-peer applications. It provides a
secure transport channel for [`go-libp2p`][go-libp2p] based on the 
[Noise Protocol Framework](https://noiseprotocol.org). Following an initial
plaintext handshake, all data exchanged between peers using `go-libp2p-noise` is
encrypted and protected from eavesdropping.

libp2p supports multiple [transport protocols][docs-transport], many of which
lack native channel security. `go-libp2p-noise` is designed to work with
go-libp2p's ["transport upgrader"][transport-upgrader], which applies security
modules (like `go-libp2p-noise`) to an insecure channel. `go-libp2p-noise`
implements the [`SecureTransport` interface][godoc-securetransport], which
allows the upgrader to secure any underlying connection.

More detail on the handshake protocol and wire format used is available in the
[noise-libp2p specification][noise-libp2p-spec]. Details about security protocol
negotiation in libp2p can be found in the [connection establishment spec][conn-spec].

## Status

This implementation is being updated to track some recent changes to the [spec][noise-libp2p-spec]:

- [ ] [use of channel binding token to prevent replay attacks](https://github.com/libp2p/specs/pull/234)

We recommend waiting until those changes are in place before adopting go-libp2p-noise for production use.

## Install

As `go-libp2p-noise` is still in development, it is not included as a default dependency of `go-libp2p`.

`go-libp2p-noise` is a standard Go module which can be installed with:

```sh
go get github.com/libp2p/go-libp2p-noise
```

This repo is [gomod](https://github.com/golang/go/wiki/Modules)-compatible, and users of
go 1.11 and later with modules enabled will automatically pull the latest tagged release
by referencing this package. Upgrades to future releases can be managed using `go get`,
or by editing your `go.mod` file as [described by the gomod documentation](https://github.com/golang/go/wiki/Modules#how-to-upgrade-and-downgrade-dependencies).

## Usage

`go-libp2p-noise` is not currently enabled by default when constructing a new libp2p
[Host][godoc-host], so you will need to explicitly enable it in order to use it.

To add `go-libp2p-noise` to the default set of security protocols, you can extend the
`DefaultSecurity` [package variable in go-libp2p][godoc-go-libp2p-pkg-vars] with
a new [`Security` option][godoc-security-option] that enables `go-libp2p-noise`:

```go
package example

import (
  "context"
  libp2p "github.com/libp2p/go-libp2p"
  noise "github.com/libp2p/go-libp2p-noise"
)

ctx := context.Background() // you may want a more specialized context in the real world
security := libp2p.ChainOptions(
  libp2p.DefaultSecurity,
  libp2p.Security(noise.ID, noise.NewTransport))

host := libp2p.New(ctx, security)
```

If you _only_ want to use `go-libp2p-noise`, you can simply pass in the `Security` option without chaining it
to the `DefaultSecurity` variable. However, this will limit the peers you are able to communicate with to just
those that support the Noise libp2p security protocol.

## Contribute

Feel free to join in. All welcome. Open an [issue](https://github.com/libp2p/go-libp2p-noise/issues)!

This repository falls under the libp2p [Code of Conduct](https://github.com/libp2p/community/blob/master/code-of-conduct.md).

### Want to hack on libp2p?

[![](https://cdn.rawgit.com/libp2p/community/master/img/contribute.gif)](https://github.com/libp2p/community/blob/master/CONTRIBUTE.md)

## License

MIT

---

[go-libp2p]: https://github.com/libp2p/go-libp2p
[noise-libp2p-spec]: https://github.com/libp2p/specs/blob/master/noise/README.md
[conn-spec]: https://github.com/libp2p/specs/blob/master/connections/README.md
[docs-transport]: https://docs.libp2p.io/concepts/transport
[transport-upgrader]: https://github.com/libp2p/go-libp2p-transport-upgrader
[godoc-host]: https://godoc.org/github.com/libp2p/go-libp2p-core/host#Host
[godoc-option]: https://godoc.org/github.com/libp2p/go-libp2p#Option
[godoc-go-libp2p-pkg-vars]: https://godoc.org/github.com/libp2p/go-libp2p#pkg-variables 
[godoc-security-option]: https://godoc.org/github.com/libp2p/go-libp2p#Security
[godoc-securetransport]: https://godoc.org/github.com/libp2p/go-libp2p-core/sec#SecureTransport
