#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let mirage = Conf.with_pkg ~default:false "mirage"
let coverage = Conf.with_pkg ~default:false "coverage"

let distrib =
  let exclude_paths () = Pkg.exclude_paths () >>| fun ps -> "bench" :: ps in
  Pkg.distrib ~exclude_paths ()

let cmd c os files =
  let build =
    if Conf.value c coverage then
      let coverage_arg = Cmd.(v "-pkg" % "bisect_ppx") in
      let coverage_cmd c os = Cmd.(Pkg.build_cmd c os %% coverage_arg) in
      coverage_cmd
    else
      Pkg.build_cmd
  in
  OS.Cmd.run @@ Cmd.(build c os %% of_list files)

let () =
  Pkg.describe ~build:(Pkg.build ~cmd ()) "arp" @@ fun c ->
  let mirage = Conf.value c mirage in
  Ok [
    Pkg.mllib "src/arp.mllib";
    Pkg.mllib ~cond:mirage "mirage/arp-mirage.mllib";
    Pkg.test "test/tests"
  ]
