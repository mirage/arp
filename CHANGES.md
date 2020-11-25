## v2.3.1 (2020-11-25)

* Fix opam file to include mirage-profile dependency (#21 @hannesm)

## v2.3.0 (2020-11-25)

* Update to dune 2 (#19 @hannesm)
* Merge opam packages into a single one (#20 @hannesm)

## v2.2.1 (2019-12-17)

* adapt to lwt 5.0.0 change (#18 @hannesm)

## v2.2.0 (2019-10-30)

* adapt to mirage-protocols 4.0.0 changes (#17 @hannesm)

## v2.1.0 (2019-07-16)

* Update to ipaddr.4.0.0 interfaces (#16 @avsm)

## v2.0.0 (2019-02-24)

* provide Arp_packet.size
* Arp_handler API changes: return Arp_packet.t instead of Cstruct.t
* adapt to ethernet 2.0.0 changes

## v1.0.0 (2019-02-02)

* split opam package into two separate ones: a core
  `arp` package and the `arp-mirage` implementation
  for MirageOS that has more dependencies.  This
  eliminates the use of depopts that was done previously
  to build the Mirage layer. (#7 @avsm)

* port build system to Dune (#7 @avsm). The `make coverage`
  and `make bench` targets will do the job of the previous
  topkg targets for those.

* minor fixes to ocamldoc comments to be compatible with
  odoc.

* use mirage-random and mirage-random-test instead of a
  nocrypto dependency in tests and bench (#7 @hannesm)

* import tests from mirage-tcpip (#8 @hannesm)

* depend on the ethernet opam package, no longer provided
  by tcpip >3.7.0 (#9 @hannesm)

## 0.2.3 (2019-01-04)

* port to ipaddr 3.0.0

## 0.2.2 (2018-08-25)

* remove Arp_wire module, now integrated into Arp_packet
* remove usage of ppx_cstruct

## 0.2.1 (2018-05-06)

* Avoid an initial gratitious ARP with Ipaddr.V4.any

## 0.2.0 (2017-01-17)

* MirageOS3 support
* Don't ship with -warn-error +A, use it only in `./build`
* Fix testsuite compilation on OCaml 4.02
* Renamed `Marp` to `Arpv4` (same as MirageOS ARP handler in tcpip)

## 0.1.1 (2016-07-13)

* Minor nits for topkg

## 0.1.0 (2016-07-12)

* Initial release
