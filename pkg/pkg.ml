#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let mirage = Conf.with_pkg ~default:false "mirage"

let distrib =
  let exclude_paths () = Pkg.exclude_paths () >>| fun ps -> "bench" :: ps in
  Pkg.distrib ~exclude_paths ()

let () =
  let opams =
    [ Pkg.opam_file "opam" ~lint_deps_excluding:(Some ["ppx_tools"]) ]
  in
  Pkg.describe ~opams "arp" @@ fun c ->
  let mirage = Conf.value c mirage in
  Ok [
    Pkg.mllib "src/arp.mllib";
    Pkg.mllib ~cond:mirage "mirage/arpv4.mllib" ~dst_dir:"mirage/";
    Pkg.test "test/tests"
  ]
