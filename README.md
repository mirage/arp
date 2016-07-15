## ARP - Address Resolution Protocol purely in OCaml

%%VERSION%%

ARP is an implementation of the address resolution protocol purely in OCaml.  It
handles IPv4 protocol addresses and Ethernet hardware addresses only.

A MirageOS
[V1.ARP](https://github.com/mirage/mirage/blob/v2.9.0/types/V1.mli#L471)
implementation (using Lwt) is in the `mirage` subdirectory.

Motivation for this implementation is [written up](https://hannes.nqsb.io/Posts/ARP).

## Documentation

[API Documentation](https://hannesm.github.io/arp/doc/) is available online,
also a test suite and a [coverage
report](https://hannesm.github.io/arp/coverage/).

## Installation

`opam install arp` will install this library, once you have installed OCaml (>=
4.02.0) and opam (>= 1.2.2).

The Mirage interface depends on changes in the not yet released tcpip library,
in order to get the latest, you'll need to `opam pin add -k git --dev
mirage-types && opam pin add -k git --dev tcpip`.

Benchmarks require more opam libraries, namely `mirage-vnetif mirage-clock-unix
mirage-unix nocrypto`.  Use `./build bench` (and `./build mbench` for the same
code using the ARPv4 implementation provided by `tcpip`).
