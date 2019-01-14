## ARP - Address Resolution Protocol purely in OCaml

%%VERSION%%

ARP is an implementation of the address resolution protocol (RFC826) purely in
OCaml.  It handles IPv4 protocol addresses and Ethernet hardware addresses only.

A [MirageOS](https://mirage.io)
[Mirage_protocols.ARP](https://github.com/mirage/mirage-protocols/blob/4776d2ab1d8c5b1bfd69d46583779c2caef7b5e8/src/mirage_protocols.mli#L169)
implementation is in the `mirage` subdirectory.

Motivation for this implementation is [written up](https://hannes.nqsb.io/Posts/ARP).

## Documentation

[![Build Status](https://travis-ci.org/mirage/arp.svg?branch=master)](https://travis-ci.org/mirage/arp)

[API documentation](https://mirage.github.io/arp/) is available online.

## Installation

`opam install arp` will install this library, once you have installed OCaml (>=
4.04.0) and opam (>= 2.0.0).

Benchmarks require more opam libraries, namely `mirage-vnetif mirage-clock-unix
mirage-unix mirage-random-test`.  Use `make bench` to build and run it.
