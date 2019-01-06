## ARP - Address Resolution Protocol purely in OCaml

%%VERSION%%

ARP is an implementation of the address resolution protocol (RFC826) purely in
OCaml.  It handles IPv4 protocol addresses and Ethernet hardware addresses only.

A MirageOS
[Mirage_protocols.ARP](https://github.com/mirage/mirage-protocols/blob/4776d2ab1d8c5b1bfd69d46583779c2caef7b5e8/src/mirage_protocols.mli#L169)
implementation is in the `mirage` subdirectory.

Motivation for this implementation is [written up](https://hannes.nqsb.io/Posts/ARP).

## Documentation

[![Build Status](https://travis-ci.org/hannesm/arp.svg?branch=master)](https://travis-ci.org/hannesm/arp)

[API documentation](https://hannesm.github.io/arp/doc/) is available online,
also a test suite and a [coverage
report](https://hannesm.github.io/arp/coverage/).

## Installation

`opam install arp` will install this library, once you have installed OCaml (>=
4.04.0) and opam (>= 2.0.0).

The Mirage interface depends on changes in the not yet released tcpip library,
in order to get the latest, you'll need to `opam repo add mirage-dev
https://github.com/mirage/mirage-dev.git`.

Benchmarks require more opam libraries, namely `mirage-vnetif mirage-clock-unix
mirage-unix nocrypto`.  Use `./bench/build.sh` to build, it will produce a
`bench.native`, which uses this implementation, and a `mbench.native` which uses
the ARPv4 implementation of mirage-tcpip.
