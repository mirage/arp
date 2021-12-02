open Lwt.Infix

let time_reduction_factor = 600

module Time = struct
  type 'a io = 'a Lwt.t
  let sleep_ns ns = Lwt_unix.sleep (Duration.to_f ns)
end
module Fast_time = struct
  type 'a io = 'a Lwt.t
  let sleep_ns time = Time.sleep_ns Int64.(div time (of_int time_reduction_factor))
end

module B = Basic_backend.Make
module V = Vnetif.Make(B)
module E = Ethernet.Make(V)
module A = Arp.Make(E)(Fast_time)

let src = Logs.Src.create "test_arp" ~doc:"Mirage ARP tester"
module Log = (val Logs.src_log src : Logs.LOG)

type arp_stack = {
  backend : B.t;
  netif: V.t;
  ethif: E.t;
  arp: A.t;
}

let first_ip = Ipaddr.V4.of_string_exn "192.168.3.1"
let second_ip = Ipaddr.V4.of_string_exn "192.168.3.10"
let sample_mac = Macaddr.of_string_exn "10:9a:dd:c0:ff:ee"

let packet = (module Arp_packet : Alcotest.TESTABLE with type t = Arp_packet.t)

let ip =
  let module M = struct
    type t = Ipaddr.V4.t
    let pp = Ipaddr.V4.pp
    let equal p q = (Ipaddr.V4.compare p q) = 0
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

let macaddr =
  let module M = struct
    type t = Macaddr.t
    let pp = Macaddr.pp
    let equal p q = (Macaddr.compare p q) = 0
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

let header_size = Ethernet_wire.sizeof_ethernet
let size = Arp_packet.size

let check_header ~message expected actual =
  Alcotest.(check packet) message expected actual

let fail = Alcotest.fail
let failf fmt = Fmt.kstr (fun s -> Alcotest.fail s) fmt

let timeout ~time t =
  let msg = Printf.sprintf "Timed out: didn't complete in %d milliseconds" time in
  Lwt.pick [ t; Time.sleep_ns (Duration.of_ms time) >>= fun () -> fail msg; ]

let check_response expected buf =
  match Arp_packet.decode buf with
  | Error s -> Alcotest.fail (Fmt.to_to_string Arp_packet.pp_error s)
  | Ok actual ->
    Alcotest.(check packet) "parsed packet comparison" expected actual

let check_ethif_response expected buf =
  let open Ethernet_packet in
  match Unmarshal.of_cstruct buf with
  | Error s -> Alcotest.fail s
  | Ok ({ethertype; _}, arp) ->
    match ethertype with
    | `ARP -> check_response expected arp
    | _ -> Alcotest.fail "Ethernet packet with non-ARP ethertype"

let garp source_mac source_ip =
  let open Arp_packet in
  {
    operation = Request;
    source_mac;
    target_mac = Macaddr.of_octets_exn "\000\000\000\000\000\000";
    source_ip;
    target_ip = source_ip;
  }

let fail_on_receipt netif buf =
  Alcotest.fail (Format.asprintf "received traffic when none was expected on interface %a: %a"
	  Macaddr.pp (V.mac netif) Cstruct.hexdump_pp buf)

let single_check netif expected =
  V.listen netif ~header_size (fun buf ->
      match Ethernet_packet.Unmarshal.of_cstruct buf with
      | Error _ -> failwith "sad face"
      | Ok (_, payload) ->
        check_response expected payload; V.disconnect netif) >|= fun _ -> ()

(*  { Ethernet_packet.source = arp.source_mac;
      destination = arp.target_mac;
      ethertype = `ARP;
    } *)

let arp_reply ~from_netif ~to_netif ~from_ip ~to_ip arp =
  let open Arp_packet in
  let a =
    { operation = Reply;
      source_mac = V.mac from_netif;
      target_mac = V.mac to_netif;
      source_ip = from_ip;
      target_ip = to_ip}
  in
  encode_into a arp ;
  Arp_packet.size

let arp_request ~from_netif ~to_mac ~from_ip ~to_ip arp =
  let open Arp_packet in
  let a =
    { operation = Request;
      source_mac = V.mac from_netif;
      target_mac = to_mac;
      source_ip = from_ip;
      target_ip = to_ip}
  in
  encode_into a arp ;
  Arp_packet.size

let get_arp ?backend () =
  let backend = match backend with
    | None -> B.create ~use_async_readers:true ~yield:Lwt.pause ()
    | Some b -> b
  in
  V.connect backend >>= fun netif ->
  E.connect netif >>= fun ethif ->
  A.connect ethif >>= fun arp ->
  Lwt.return { backend; netif; ethif; arp }

(* we almost always want two stacks on the same backend *)
let two_arp () =
  get_arp () >>= fun first ->
  get_arp ~backend:first.backend () >>= fun second ->
  Lwt.return (first, second)

(* ...but sometimes we want three *)
let three_arp () =
  get_arp () >>= fun first ->
  get_arp ~backend:first.backend () >>= fun second ->
  get_arp ~backend:first.backend () >>= fun third ->
  Lwt.return (first, second, third)

let query_or_die arp ip expected_mac =
  A.query arp ip >>= function
  | Error `Timeout ->
    Log.warn (fun f -> f "Timeout querying %a. Table contents: %a"
                 Ipaddr.V4.pp ip A.pp arp);
    fail "ARP query failed when success was mandatory";
  | Ok mac ->
    Alcotest.(check macaddr) "mismatch for expected query value" expected_mac mac;
    Lwt.return_unit
  | Error e -> failf "ARP query failed with %a" A.pp_error e

let query_and_no_response arp ip =
  A.query arp ip >>= function
  | Error `Timeout ->
    Log.warn (fun f -> f "Timeout querying %a. Table contents: %a" Ipaddr.V4.pp ip A.pp arp);
    Lwt.return_unit
  | Ok _ -> failf "expected nothing, found something in cache"
  | Error e ->
    Log.err (fun m -> m "another err");
    failf "ARP query failed with %a" A.pp_error e

let set_and_check ~listener ~claimant ip =
  A.set_ips claimant.arp [ ip ] >>= fun () ->
  Log.debug (fun f -> f "Set IP for %a to %a" Macaddr.pp (V.mac claimant.netif) Ipaddr.V4.pp ip);
  Logs.debug (fun f -> f "Listener table contents after IP set on claimant: %a" A.pp listener);
  query_or_die listener ip (V.mac claimant.netif)

let start_arp_listener stack () =
  let noop = (fun _ -> Lwt.return_unit) in
  Log.debug (fun f -> f "starting arp listener for %a" Macaddr.pp (V.mac stack.netif));
  let arpv4 frame =
    Log.debug (fun f -> f "frame received for arpv4");
    A.input stack.arp frame
  in
  E.input ~arpv4 ~ipv4:noop ~ipv6:noop stack.ethif

let not_in_cache ~listen probe arp ip =
  Lwt.pick [
    single_check listen probe;
    Time.sleep_ns (Duration.of_ms 100) >>= fun () ->
    A.query arp ip >>= function
    | Ok _ -> failf "entry in cache when it shouldn't be %a" Ipaddr.V4.pp ip
    | Error `Timeout -> Lwt.return_unit
    | Error e -> failf "error for %a while reading the cache: %a"
                   Ipaddr.V4.pp ip A.pp_error e
  ]

let set_ip_sends_garp () =
  two_arp () >>= fun (speak, listen) ->
  let emit_garp =
    Time.sleep_ns (Duration.of_ms 100) >>= fun () ->
    A.set_ips speak.arp [ first_ip ] >>= fun () ->
    Alcotest.(check (list ip)) "garp emitted when setting ip" [ first_ip ] (A.get_ips speak.arp);
    Lwt.return_unit
  in
  let expected_garp = garp (V.mac speak.netif) first_ip in
  timeout ~time:500 (
  Lwt.join [
    single_check listen.netif expected_garp;
    emit_garp;
  ]) >>= fun () ->
  (* now make sure we have consistency when setting *)
  A.set_ips speak.arp [] >>= fun () ->
  Alcotest.(check (slist ip Ipaddr.V4.compare)) "list of bound IPs on initialization" [] (A.get_ips speak.arp);
  A.set_ips speak.arp [ first_ip; second_ip ] >>= fun () ->
  Alcotest.(check (slist ip Ipaddr.V4.compare)) "list of bound IPs after setting two IPs"
    [ first_ip; second_ip ] (A.get_ips speak.arp);
  Lwt.return_unit

let add_get_remove_ips () =
  get_arp () >>= fun stack ->
  let check str expected =
    Alcotest.(check (list ip)) str expected (A.get_ips stack.arp)
  in
  check "bound ips is an empty list on startup" [];
  A.set_ips stack.arp [ first_ip; first_ip ] >>= fun () ->
  check "set ips with duplicate elements result in deduplication" [first_ip];
  A.remove_ip stack.arp first_ip >>= fun () ->
  check "ip list is empty after removing only ip" [];
  A.remove_ip stack.arp first_ip >>= fun () ->
  check "ip list is empty after removing from empty list" [];
  A.add_ip stack.arp first_ip >>= fun () ->
  check "first ip is the only member of the set of bound ips" [first_ip];
  A.add_ip stack.arp first_ip >>= fun () ->
  check "adding ips is idempotent" [first_ip];
  Lwt.return_unit

let input_single_garp () =
  two_arp () >>= fun (listen, speak) ->
  (* set the IP on speak_arp, which should cause a GARP to be emitted which
     listen_arp will hear and cache. *)
  let one_and_done buf =
    let arpbuf = Cstruct.shift buf 14 in
    A.input listen.arp arpbuf >>= fun () ->
    V.disconnect listen.netif
  in
  timeout ~time:500 (
    Lwt.join [
      (V.listen listen.netif ~header_size one_and_done >|= fun _ -> ());
      Time.sleep_ns (Duration.of_ms 100) >>= fun () ->
      Lwt.async (fun () -> A.query listen.arp first_ip >|= ignore) ;
      A.set_ips speak.arp [ first_ip ];
    ])
    >>= fun () ->
  (* try a lookup of the IP set by speak.arp, and fail if this causes listen_arp
     to block or send an ARP query -- listen_arp should answer immediately from
     the cache.  An attempt to resolve via query will result in a timeout, since
     speak.arp has no listener running and therefore won't answer any arp
     who-has requests. *)
    timeout ~time:500 (query_or_die listen.arp first_ip (V.mac speak.netif)) (* >>= fun () ->
                                                                                Time.sleep_ns (Duration.of_sec 5) *)

let input_single_unicast () =
  two_arp () >>= fun (listen, speak) ->
  (* contrive to make a reply packet for the listener to hear *)
  let for_listener =
    arp_reply
      ~from_netif:speak.netif ~to_netif:listen.netif
      ~from_ip:first_ip ~to_ip:second_ip
  in
  let listener = start_arp_listener listen () in
  timeout ~time:500 (
  Lwt.choose [
    (V.listen listen.netif ~header_size listener >|= fun _ -> ());
    Time.sleep_ns (Duration.of_ms 2) >>= fun () ->
    E.write speak.ethif (V.mac listen.netif) `ARP ~size for_listener >>= fun _ ->
    query_and_no_response listen.arp first_ip
  ])

let input_resolves_wait () =
  two_arp () >>= fun (listen, speak) ->
  (* contrive to make a reply packet for the listener to hear *)
  let for_listener = arp_reply ~from_netif:speak.netif ~to_netif:listen.netif
                         ~from_ip:first_ip ~to_ip:second_ip in
  (* initiate query when the cache is empty.  On resolution, fail for a timeout
     and test the MAC if resolution was successful, then disconnect the
     listening interface to ensure the test terminates.
     Fail with a timeout message if the whole thing takes more than 5s. *)
  let listener = start_arp_listener listen () in
  let query_then_disconnect =
    query_or_die listen.arp first_ip (V.mac speak.netif) >>= fun () ->
    V.disconnect listen.netif
  in
  timeout ~time:5000 (
    Lwt.join [
      (V.listen listen.netif ~header_size listener >|= fun _ -> ());
      query_then_disconnect;
      Time.sleep_ns (Duration.of_ms 1) >>= fun () ->
      E.write speak.ethif (V.mac listen.netif) `ARP ~size for_listener >|= function
      | Ok x -> x
      | Error _ -> failf "ethernet write failed"
    ]
  )

let unreachable_times_out () =
  get_arp () >>= fun speak ->
  A.query speak.arp first_ip >>= function
  | Ok _ -> failf "query claimed success when impossible for %a" Ipaddr.V4.pp first_ip
  | Error `Timeout -> Lwt.return_unit
  | Error e -> failf "error waiting for a timeout: %a" A.pp_error e

let input_replaces_old () =
  three_arp () >>= fun (listen, claimant_1, claimant_2) ->
  (* query for IP to accept responses *)
  Lwt.async (fun () -> A.query listen.arp first_ip >|= ignore) ;
  Lwt.async (fun () ->
      Log.debug (fun f -> f "arp listener started");
      V.listen listen.netif ~header_size (start_arp_listener listen ()) >|= fun _ -> ());
  timeout ~time:2000 (
    set_and_check ~listener:listen.arp ~claimant:claimant_1 first_ip >>= fun () ->
    set_and_check ~listener:listen.arp ~claimant:claimant_2 first_ip >>= fun () ->
    V.disconnect listen.netif
    )

let entries_expire () =
  two_arp () >>= fun (listen, speak) ->
  A.set_ips listen.arp [ second_ip ] >>= fun () ->
  (* here's what we expect listener to emit once its cache entry has expired *)
  let expected_arp_query =
    Arp_packet.({operation = Request;
                 source_mac = V.mac listen.netif;
                 target_mac = Macaddr.broadcast;
                 source_ip = second_ip; target_ip = first_ip})
  in
  (* query for IP to accept responses *)
  Lwt.async (fun () -> A.query listen.arp first_ip >|= ignore) ;
  Lwt.async (fun () -> V.listen listen.netif ~header_size (start_arp_listener listen ()) >|= fun _ -> ());
  let test =
    Time.sleep_ns (Duration.of_ms 10) >>= fun () ->
    set_and_check ~listener:listen.arp ~claimant:speak first_ip >>= fun () ->
    (* sleep for 5s to make sure we hit `tick` often enough *)
    Time.sleep_ns (Duration.of_sec 5) >>= fun () ->
    (* asking now should generate a query *)
    not_in_cache ~listen:speak.netif expected_arp_query listen.arp first_ip
  in
  timeout ~time:7000 test

(* RFC isn't strict on how many times to try, so we'll just say any number
   greater than 1 is fine *)
let query_retries () =
  two_arp () >>= fun (listen, speak) ->
  let expected_query = Arp_packet.({source_mac = V.mac speak.netif;
                                    target_mac = Macaddr.broadcast;
                                    source_ip = Ipaddr.V4.any;
                                    target_ip = first_ip;
                                    operation = Request;})
  in
  let how_many = ref 0 in
  let listener buf =
    check_ethif_response expected_query buf;
    if !how_many = 0 then begin
      how_many := !how_many + 1;
      Lwt.return_unit
    end else V.disconnect listen.netif
  in
  let ask () =
    A.query speak.arp first_ip >>= function
    | Error e -> failf "Received error before >1 query: %a" A.pp_error e
    | Ok _ -> failf "got result from query for %a, erroneously" Ipaddr.V4.pp first_ip
  in
  Lwt.pick [
    (V.listen listen.netif ~header_size listener >|= fun _ -> ());
    Time.sleep_ns (Duration.of_ms 2) >>= ask;
    Time.sleep_ns (Duration.of_sec 6) >>= fun () ->
    fail "query didn't succeed or fail within 6s"
  ]

(* requests for us elicit a reply *)
let requests_are_responded_to () =
  let (answerer_ip, inquirer_ip) = (first_ip, second_ip) in
  two_arp () >>= fun (inquirer, answerer) ->
  (* neither has a listener set up when we set IPs, so no GARPs in the cache *)
  A.add_ip answerer.arp answerer_ip >>= fun () ->
  A.add_ip inquirer.arp inquirer_ip >>= fun () ->
  let request = arp_request ~from_netif:inquirer.netif ~to_mac:Macaddr.broadcast
      ~from_ip:inquirer_ip ~to_ip:answerer_ip
  in
  let expected_reply =
    Arp_packet.({ operation = Reply;
                  source_mac = V.mac answerer.netif;
                  target_mac = V.mac inquirer.netif;
                  source_ip = answerer_ip; target_ip = inquirer_ip})
  in
  let listener close_netif buf =
    check_ethif_response expected_reply buf;
    V.disconnect close_netif
  in
  let arp_listener =
    V.listen answerer.netif ~header_size (start_arp_listener answerer ()) >|= fun _ -> ()
  in
  timeout ~time:1000 (
    Lwt.join [
      (* listen for responses and check them against an expected result *)
      (V.listen inquirer.netif ~header_size (listener inquirer.netif) >|= fun _ -> ());
      (* start the usual ARP listener, which should respond to requests *)
      arp_listener;
      (* send a request for the ARP listener to respond to *)
      Time.sleep_ns (Duration.of_ms 100) >>= fun () ->
      E.write inquirer.ethif Macaddr.broadcast `ARP ~size request >>= fun _ ->
      Time.sleep_ns (Duration.of_ms 100) >>= fun () ->
      V.disconnect answerer.netif
    ];
  )

let requests_not_us () =
  let (answerer_ip, inquirer_ip) = (first_ip, second_ip) in
  two_arp () >>= fun (answerer, inquirer) ->
  A.add_ip answerer.arp answerer_ip >>= fun () ->
  A.add_ip inquirer.arp inquirer_ip >>= fun () ->
  let ask ip buf =
    let open Arp_packet in
    encode_into
      { operation = Request;
        source_mac = V.mac inquirer.netif; target_mac = Macaddr.broadcast;
        source_ip = inquirer_ip; target_ip = ip }
      buf ;
    size
  in
  let requests = List.map ask [ inquirer_ip; Ipaddr.V4.any;
                                Ipaddr.V4.of_string_exn "255.255.255.255" ] in
  let make_requests =
    Lwt_list.iter_s (fun b -> E.write inquirer.ethif Macaddr.broadcast `ARP ~size b >|= fun _ -> ())
      requests
  in
  let disconnect_listeners () =
    Lwt_list.iter_s (V.disconnect) [answerer.netif; inquirer.netif]
  in
  Lwt.join [
    (V.listen answerer.netif ~header_size (start_arp_listener answerer ()) >|= fun _ -> ());
    (V.listen inquirer.netif ~header_size (fail_on_receipt inquirer.netif) >|= fun _ -> ());
    make_requests >>= fun _ ->
    Time.sleep_ns (Duration.of_ms 100) >>=
    disconnect_listeners
  ]

let nonsense_requests () =
  let (answerer_ip, inquirer_ip) = (first_ip, second_ip) in
  three_arp () >>= fun (answerer, inquirer, checker) ->
  A.set_ips answerer.arp [ answerer_ip ] >>= fun () ->
  let request number arp =
    let open Arp_packet in
    encode_into
      { operation = Request;
	source_mac = V.mac inquirer.netif;
	target_mac = Macaddr.broadcast;
	source_ip = inquirer_ip;
	target_ip = answerer_ip } arp ;
    Cstruct.BE.set_uint16 arp 6 number;
    Arp_packet.size
  in
  let requests = List.map request [0; 3; -1; 255; 256; 257; 65536] in
  let make_requests =
    Lwt_list.iter_s (fun l -> E.write inquirer.ethif Macaddr.broadcast `ARP ~size l >|= fun _ -> ()) requests in
  let expected_probe = Arp_packet.{ operation = Request;
                                    source_mac = V.mac answerer.netif;
                                    source_ip = answerer_ip;
                                    target_mac = Macaddr.broadcast;
                                    target_ip = inquirer_ip; }
  in
  Lwt.async (fun () -> V.listen answerer.netif ~header_size (start_arp_listener answerer ()) >|= fun _ -> ());
  timeout ~time:1000 (
    Lwt.join [
      (V.listen inquirer.netif ~header_size (fail_on_receipt inquirer.netif) >|= fun _ -> ());
      make_requests >>= fun () ->
      V.disconnect inquirer.netif >>= fun () ->
      (* not sufficient to just check to see whether we've replied; it's equally
         possible that we erroneously make a cache entry.  Make sure querying
         inquirer_ip results in an outgoing request. *)
      not_in_cache ~listen:checker.netif expected_probe answerer.arp inquirer_ip
    ] )

let packet () =
  let first_mac  = Macaddr.of_string_exn "10:9a:dd:01:23:45" in
  let second_mac = Macaddr.of_string_exn "00:16:3e:ab:cd:ef" in
  let example_request =
    Arp_packet.{ operation = Request;
                 source_mac = first_mac;
                 target_mac = second_mac;
                 source_ip = first_ip;
                 target_ip = second_ip;
               }
  in
  let marshalled = Arp_packet.encode example_request in
  match Arp_packet.decode marshalled with
  | Error _ -> Alcotest.fail "couldn't unmarshal something we made ourselves"
  | Ok unmarshalled ->
    Alcotest.(check packet) "serialize/deserialize" example_request unmarshalled;
    Lwt.return_unit

let suite =
  [
    "conversions neither lose nor gain information", `Quick, packet;
    "nonsense requests are ignored", `Quick, nonsense_requests;
    "requests are responded to", `Quick, requests_are_responded_to;
    "entries expire", `Quick, entries_expire;
    "irrelevant requests are ignored", `Quick, requests_not_us;
    "set_ip sets ip, sends GARP", `Quick, set_ip_sends_garp;
    "add_ip, get_ip and remove_ip as advertised", `Quick, add_get_remove_ips;
    "GARPs are heard and not cached", `Quick, input_single_garp;
    "unsolicited unicast replies are heard and not cached", `Quick, input_single_unicast;
    "solicited unicast replies resolve pending threads", `Quick, input_resolves_wait;
    "entries are replaced with new information", `Quick, input_replaces_old;
    "unreachable IPs time out", `Quick, unreachable_times_out;
    "queries are tried repeatedly before timing out", `Quick, query_retries;
  ]

let run test () =
  Lwt_main.run (test ())

let () =
  (* enable logging to stdout for all modules *)
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level ~all:true (Some Logs.Debug);
  let suite =
    [ "arp", List.map (fun (d, s, f) -> d, s, run f) suite ]
  in
  Alcotest.run "arp" suite
