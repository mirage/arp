(* derived from ISC-licensed mirage-tcpip/lib_test/test_arp.ml *)

let hdr =
  let buf = Cstruct.create 6 in
  Cstruct.BE.set_uint16 buf 0 1 ;
  Cstruct.BE.set_uint16 buf 2 0x0800 ;
  Cstruct.set_uint8 buf 4 6 ;
  Cstruct.set_uint8 buf 5 4 ;
  buf

let gen_int () =
  let buf = Nocrypto.Rng.generate 1 in
  Cstruct.get_uint8 buf 0

let gen_op () =
  let op = gen_int () in
  let buf = Cstruct.create 2 in
  let op = 1 + op mod 2 in
  Cstruct.BE.set_uint16 buf 0 op ;
  buf

let gen_arp () =
  let addresses = Nocrypto.Rng.generate 20
  and opb = gen_op ()
  in
  Cstruct.concat [ hdr ; opb ; addresses ]

let gen_req () =
  let addresses = Nocrypto.Rng.generate 20
  and opb = Cstruct.create 2
  in
  Cstruct.BE.set_uint16 opb 0 1 ;
  Cstruct.concat [ hdr ; opb ; addresses ]

let gen_ip () =
  let last = Nocrypto.Rng.generate 1 in
  let ip = "\010\000\000" ^ (Cstruct.to_string last) in
  Ipaddr.V4.of_bytes_exn ip

let ip = Ipaddr.V4.of_string_exn "10.0.0.0"
let mac = Macaddr.of_string_exn "00:de:ad:be:ef:00"

let gen_rep () =
  let omac = Nocrypto.Rng.generate 6
  and oip = gen_ip ()
  and opb = Cstruct.create 2
  in
  Cstruct.BE.set_uint16 opb 0 2 ;
  let add = String.concat "" [
      Ipaddr.V4.to_bytes oip ;
      Macaddr.to_bytes mac ;
      Ipaddr.V4.to_bytes ip
    ] in
  Cstruct.concat [ hdr ; opb ; omac ; Cstruct.of_string add ]

let other_ip = Ipaddr.V4.of_string_exn "10.0.0.1"
let other_mac = Macaddr.of_string_exn "00:de:ad:be:ef:01"

let myreq =
  let req = Cstruct.create 2 in
  Cstruct.BE.set_uint16 req 0 1 ;
  let addresses = String.concat "" [
      Macaddr.to_bytes other_mac; Ipaddr.V4.to_bytes other_ip ;
      Macaddr.to_bytes mac; Ipaddr.V4.to_bytes ip
    ]
  in
  Cstruct.concat [ hdr ; req ; Cstruct.of_string addresses ]

open Lwt.Infix

let time_reduction_factor = 60.

module Fast_clock = struct

  let last_read = ref (Clock.time ())

  (* from mirage/types/V1.mli module type CLOCK *)
  type tm =
    { tm_sec: int;               (** Seconds 0..60 *)
      tm_min: int;               (** Minutes 0..59 *)
      tm_hour: int;              (** Hours 0..23 *)
      tm_mday: int;              (** Day of month 1..31 *)
      tm_mon: int;               (** Month of year 0..11 *)
      tm_year: int;              (** Year - 1900 *)
      tm_wday: int;              (** Day of week (Sunday is 0) *)
      tm_yday: int;              (** Day of year 0..365 *)
      tm_isdst: bool;            (** Daylight time savings in effect *)
    }

  let gmtime time =
    let tm = Clock.gmtime time in
    {
      tm_sec = tm.Clock.tm_sec;
      tm_min = tm.Clock.tm_min;
      tm_hour = tm.Clock.tm_hour;
      tm_mday = tm.Clock.tm_mday;
      tm_mon = tm.Clock.tm_mon;
      tm_year = tm.Clock.tm_year;
      tm_wday = tm.Clock.tm_wday;
      tm_yday = tm.Clock.tm_yday;
      tm_isdst = tm.Clock.tm_isdst;
    }

  let time () =
    let this_time = Clock.time () in
    let clock_diff = ((this_time -. !last_read) *. time_reduction_factor) in
    last_read := this_time;
    this_time +. clock_diff

end

module Fast_time = struct
  type 'a io = 'a Lwt.t
  let sleep time = OS.Time.sleep (time /. time_reduction_factor)
end

module B = Basic_backend.Make
module V = Vnetif.Make(B)
module E = Ethif.Make(V)
(* module A = Arpv4.Make(E)(Fast_clock)(Fast_time) *)
module A = Arpv4.Make(E)(Clock)(OS.Time)

let c = ref 0
let gen arp () =
  c := !c mod 100 ;
  match !c with
  | x when x >= 00 && x < 10 -> Nocrypto.Rng.generate (gen_int ())
  | x when x >= 10 && x < 20 -> gen_req ()
  | x when x >= 20 && x < 50 -> myreq
  | x when x >= 50 && x < 80 ->
    if x mod 2 = 0 then
      (let rand = gen_int () in
       for _i = 0 to rand do
         let ip = gen_ip () in
         Lwt.async (fun () -> A.query arp ip)
       done) ;
    gen_rep ()
  | x when x >= 80 && x < 100 -> gen_arp ()
  | _ -> invalid_arg "bla"

let count2 = ref 0

let rec query arp () =
  incr count2 ;
  let ip = gen_ip () in
  Lwt.async (fun () -> A.query arp ip) ;
  OS.Time.sleep 0.0001 >>= fun () ->
  query arp ()

type arp_stack = {
  backend : B.t;
  netif: V.t;
  ethif: E.t;
  arp: A.t;
}

let or_error name fn t =
  fn t >>= function
  | `Error _ -> invalid_arg ("or_error starting " ^ name)
  | `Ok t    -> Lwt.return t

let get_arp ?(backend = B.create ~use_async_readers:true
                ~yield:(fun() -> Lwt_main.yield ()) ()) () =
  or_error "backend" V.connect backend >>= fun netif ->
  or_error "ethif" E.connect netif >>= fun ethif ->
  or_error "arp" A.connect ethif >>= fun arp ->
  Lwt.return { backend; netif; ethif; arp }

let rec send netif gen () =
  V.write netif (gen ()) >>= fun () ->
  send netif gen ()

let runit () =
  Printf.printf "starting\n%!";
  get_arp () >>= fun stack ->
  get_arp ~backend:stack.backend () >>= fun other ->
  A.set_ips stack.arp [ip] >>= fun () ->
  let count = ref 0 in
  Lwt.pick [
    V.listen stack.netif (fun b -> incr count ; A.input stack.arp b);
    send other.netif (fun () -> Nocrypto.Rng.generate 28) () ;
    OS.Time.sleep 5.0
  ] >>= fun () ->
  Printf.printf "%d random input\n%!" !count ;
  count := 0 ;
  Lwt.pick [
    V.listen stack.netif (fun b -> incr count ; A.input stack.arp b);
    send other.netif gen_arp () ;
    OS.Time.sleep 5.0
  ] >>= fun () ->
  Printf.printf "%d random ARP input\n%!" !count ;
  count := 0 ;
  Lwt.pick [
    V.listen stack.netif (fun b -> incr count ; A.input stack.arp b);
    send other.netif gen_req () ;
    OS.Time.sleep 5.0
  ] >>= fun () ->
  Printf.printf "%d requests\n%!" !count ;
  count := 0 ;
  Lwt.pick [
    V.listen stack.netif (fun b -> incr count ; A.input stack.arp b);
    send other.netif gen_rep () ;
    OS.Time.sleep 5.0
  ] >>= fun () ->
  Printf.printf "%d replies\n%!" !count ;
  count := 0 ;
  Lwt.pick [
    V.listen stack.netif (fun b -> incr count ; A.input stack.arp b);
    send other.netif (gen stack.arp) () ;
    OS.Time.sleep 5.0
  ] >>= fun () ->
  Printf.printf "%d mixed\n%!" !count ;
  count := 0 ;
  Lwt.pick [
    V.listen stack.netif (fun b -> incr count ; A.input stack.arp b);
    send other.netif gen_rep  () ;
    query stack.arp () ;
    OS.Time.sleep 5.0
  ] >|= fun () ->
  Printf.printf "%d queries (%d qs)\n%!" !count !count2

let () =
  Nocrypto_entropy_unix.initialize () ;
  Lwt_main.run (runit ()) ;
  count2 := 0 ;
  Lwt_main.run (runit ()) ;
  count2 := 0 ;
  Lwt_main.run (runit ())
