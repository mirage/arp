#!/bin/sh

OCAMLBUILD="ocamlbuild -classic-display -use-ocamlfind"

BENCH="-pkg mirage-vnetif -pkg lwt -pkg ipaddr -pkg tcpip.ethif -pkg mirage-unix -pkg mirage-clock-unix -pkg mirage-types -pkg nocrypto -pkg nocrypto.unix -pkg lwt.unix"

$OCAMLBUILD $BENCH -I mirage bench/bench.native

cp bench/bench.ml bench/mbench.ml
$OCAMLBUILD $BENCH -pkg tcpip.arpv4 bench/mbench.native
