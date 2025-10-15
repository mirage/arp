let generate n =
  let data = Cstruct.create n in
  for i = 0 to pred n do
    Cstruct.set_uint8 data i (Random.int 256)
  done;
  data

let rec gen_ip () =
  let buf = generate 4 in
  let ip = Ipaddr.V4.of_octets_exn (Cstruct.to_string buf) in
  if ip = Ipaddr.V4.any || ip = Ipaddr.V4.broadcast then
    gen_ip ()
  else
    buf, ip

let rec gen_mac () =
  let buf = generate 6 in
  let mac = Macaddr.of_octets_exn (Cstruct.to_string buf) in
  if mac = Macaddr.broadcast then
    gen_mac ()
  else
    buf, mac

let hdr = Cstruct.of_string "\000\001\008\000\006\004"

let gen_int () =
  let buf = generate 1 in
  (buf, Cstruct.get_uint8 buf 0)

let gen_op () =
  let _, op = gen_int () in
  let buf = Cstruct.create 2 in
  let op = 1 + op mod 2 in
  Cstruct.BE.set_uint16 buf 0 op ;
  (if op = 1 then Arp_packet.Request else Arp_packet.Reply), buf

let gen_arp () =
  let sm, source_mac = gen_mac ()
  and si, source_ip = gen_ip ()
  and tm, target_mac = gen_mac ()
  and ti, target_ip = gen_ip ()
  and op, opb = gen_op ()
  in
  { Arp_packet.operation = op ; source_mac ; source_ip ; target_mac ; target_ip },
  Cstruct.concat [ hdr ; opb ; sm ; si ; tm ; ti ]

let p =
  let module M = struct
    type t = Arp_packet.t
    let pp = Arp_packet.pp
    let equal s t =
        let open Arp_packet in
        s.operation = t.operation &&
        Macaddr.compare s.source_mac t.source_mac = 0 &&
        Macaddr.compare s.target_mac t.target_mac = 0 &&
        Ipaddr.V4.compare s.source_ip t.source_ip = 0 &&
        Ipaddr.V4.compare s.target_ip t.target_ip = 0
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

module Coding = struct
  let gen_op_arp () =
    let rec gen_op () =
      let buf = generate 2 in
      match Cstruct.BE.get_uint16 buf 0 with
      | 1 | 2 -> gen_op ()
      | x -> (x, buf)
    in
    let data = generate 20
    and o, opb = gen_op ()
    in
    o, Cstruct.concat [ hdr ; opb ; data ]

  let rec gen_unhandled_arp () =
    (* some consistency -- hlen and plen *)
    let htype = generate 2
    and ptype = generate 2
    in
    (* if we don't have at least length m, we'll end up in Too_short *)
    let rec i_min m () =
      let buf, len = gen_int () in
      if len < m then i_min m ()
      else buf, len
    in
    let hl, hlen = i_min 6 ()
    and pl, plen = i_min 4 ()
    in
    let my_hdr = Cstruct.concat [ htype ; ptype ; hl ; pl ] in
    if Cstruct.equal my_hdr hdr then
      gen_unhandled_arp ()
    else
      let rec gen_op () =
        let buf = generate 2 in
        match Cstruct.BE.get_uint16 buf 0 with
        | 1 | 2 -> gen_op ()
        | _ -> buf
      in
      let op = gen_op ()
      and sha = generate hlen
      and tha = generate hlen
      and spa = generate plen
      and tpa = generate plen
      in
      Cstruct.concat [ my_hdr ; op ; sha ; spa ; tha ; tpa ]

  let gen_short_arp () =
    let _, l = gen_int () in
    generate (l mod 28)

  let e =
    let module M = struct
      type t = Arp_packet.error
      let pp = Arp_packet.pp_error
      let equal a b =
        let open Arp_packet in
        match a, b with
        | Too_short, Too_short -> true
        | Unusable, Unusable -> true
        | Unknown_operation x, Unknown_operation y -> x = y
        | _ -> false
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let repeat f n () =
    for _i = 0 to n do
      f ()
    done

  let check_r s res buf =
    Alcotest.(check (result p e) s res (Arp_packet.decode buf))

  let dec_valid_arp () =
    let pkt, buf = gen_arp () in
    check_r "decoding valid ARP frames" (Ok pkt) buf

  let dec_unhandled_arp () =
    let buf = gen_unhandled_arp () in
    check_r "invalid header is error" (Error Arp_packet.Unusable) buf

  let dec_short_arp () =
    let buf = gen_short_arp () in
    check_r "short is error" (Error Arp_packet.Too_short) buf

  let dec_op_arp () =
    let o, buf = gen_op_arp () in
    check_r "invalid op is error" (Error (Arp_packet.Unknown_operation o)) buf

  let dec_enc () =
    let pkt, buf = gen_arp () in
    let cbuf = Arp_packet.encode pkt in
    Alcotest.(check bool "encoding produces same buffer" true (Cstruct.equal buf cbuf)) ;
    match Arp_packet.decode buf with
    | Error _ -> Alcotest.fail "decoding failed, should not happen"
    | Ok pack ->
      Alcotest.(check p "decoding worked" pkt pack) ;
      let cbuf = Arp_packet.encode pack in
      Alcotest.(check bool "encoding produces same buffer" true (Cstruct.equal buf cbuf))

  let enc_into () =
    let pkt, buf = gen_arp () in
    let cbuf = Cstruct.create 28 in
    Arp_packet.encode_into pkt cbuf ;
    Alcotest.(check bool "encode_into works" true (Cstruct.equal cbuf buf))

  let enc_fail () =
    for i = 0 to 27 do
      let buf = Cstruct.create i
      and pkg, _ = gen_arp ()
      in
      Alcotest.check_raises "buffer is too small" (Invalid_argument "too small")
        (fun () ->
           try Arp_packet.encode_into pkg buf with Invalid_argument _ -> invalid_arg "too small")
    done

  let coder_tsts = [
    "valid arp decoding", `Quick, (repeat dec_valid_arp 1000) ;
    "unhandled arp decoding", `Quick, (repeat dec_unhandled_arp 1000) ;
    "short arp decoding", `Quick, (repeat dec_short_arp 1000) ;
    "invalid operation decoding", `Quick, (repeat dec_op_arp 1000) ;
    "decoding is inverse of encoding", `Quick, (repeat dec_enc 1000) ;
    "encode_into works", `Quick, (repeat enc_into 1000) ;
    "encode_into fails with small bufs", `Quick, enc_fail ;
  ]
end

module Handling = struct
  let garp_of ip mac =
    let mac0 = Macaddr.of_octets_exn (String.make 6 '\000') in
    { Arp_packet.operation = Arp_packet.Request ;
      source_ip = ip ; target_ip = ip ;
      source_mac = mac ; target_mac = mac0 }

  let gen_ip () = snd (gen_ip ())
  and gen_mac () = snd (gen_mac ())

  let m =
    let module M = struct
      type t = Macaddr.t
      let pp = Macaddr.pp
      let equal a b = Macaddr.compare a b = 0
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let i =
    let module M = struct
      type t = Ipaddr.V4.t
      let pp = Ipaddr.V4.pp
      let equal a b = Ipaddr.V4.compare a b = 0
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let create_raises () =
    let mac = gen_mac () in
    Alcotest.check_raises "timeout <= 0" (Invalid_argument "timeout must be strictly positive")
      (fun () -> ignore(Arp_handler.create ~timeout:0 mac)) ;
    Alcotest.check_raises "retries < 0" (Invalid_argument "retries must be positive")
      (fun () -> ignore(Arp_handler.create ~retries:(-1) mac))

  let basic_good () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, garp = Arp_handler.create ~ipaddr mac in
    let garp = match garp with
      | None -> Alcotest.fail "expected some garp"
      | Some garp -> garp
    in
    Alcotest.(check bool "create has good GARP" true
                (Cstruct.equal (Arp_packet.encode (garp_of ipaddr mac))
                   (Arp_packet.encode (fst garp)))) ;
    Alcotest.(check (list i) "ip is sensible" [ipaddr] (Arp_handler.ips t)) ;
    Alcotest.(check (option m) "own entry is in cache"
                (Some mac) (Arp_handler.in_cache t ipaddr)) ;
    Alcotest.(check (option m) "any is not in cache" None
                (Arp_handler.in_cache t Ipaddr.V4.any)) ;
    Alcotest.(check (option m) "broadcast is not in cache" None
                (Arp_handler.in_cache t Ipaddr.V4.broadcast))

  let remove_good () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~ipaddr mac in
    Alcotest.(check (list i) "ip is sensible" [ipaddr] (Arp_handler.ips t)) ;
    Alcotest.(check (option m) "own entry is in cache"
                (Some mac) (Arp_handler.in_cache t ipaddr)) ;
    let t = Arp_handler.remove t ipaddr in
    Alcotest.(check (option m) "own entry is no longer in cache" None
                (Arp_handler.in_cache t ipaddr))

  let remove_no () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~ipaddr mac in
    Alcotest.(check (list i) "ip is sensible" [ipaddr] (Arp_handler.ips t)) ;
    Alcotest.(check (option m) "own entry is in cache"
                (Some mac) (Arp_handler.in_cache t ipaddr)) ;
    let t = Arp_handler.remove t Ipaddr.V4.any in
    Alcotest.(check (option m) "own entry is still in cache" (Some mac)
                (Arp_handler.in_cache t ipaddr))

  let alias_good () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~ipaddr mac in
    Alcotest.(check (list i) "ip is sensible" [ipaddr] (Arp_handler.ips t)) ;
    Alcotest.(check (option m) "own entry is in cache"
                (Some mac) (Arp_handler.in_cache t ipaddr)) ;
    let t, _, _ = Arp_handler.alias t ipaddr in
    Alcotest.(check (option m) "own entry is still in cache" (Some mac)
                (Arp_handler.in_cache t ipaddr)) ;
    let ip' = gen_ip () in
    let t, _, _ = Arp_handler.alias t ip' in
    Alcotest.(check (option m) "own entry is still in cache" (Some mac)
                (Arp_handler.in_cache t ipaddr)) ;
    Alcotest.(check (option m) "aliased entry is in cache" (Some mac)
                (Arp_handler.in_cache t ip'))

  let alias_remove_inverse () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~ipaddr mac in
    let ip' = gen_ip () in
    let t, _, _ = Arp_handler.alias t ip' in
    Alcotest.(check (option m) "own entry is in cache" (Some mac)
                (Arp_handler.in_cache t ipaddr)) ;
    Alcotest.(check (option m) "aliased entry is in cache" (Some mac)
                (Arp_handler.in_cache t ip')) ;
    let t = Arp_handler.remove t ip' in
    Alcotest.(check (option m) "aliased entry is no longer in cache" None
                (Arp_handler.in_cache t ip'))

  let static_good () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~ipaddr mac in
    let ip' = gen_ip () in
    let mac' = gen_mac () in
    let t, _ = Arp_handler.static t ip' mac' in
    Alcotest.(check (option m) "own entry is in cache" (Some mac)
                (Arp_handler.in_cache t ipaddr)) ;
    Alcotest.(check (option m) "static entry is in cache" (Some mac')
                (Arp_handler.in_cache t ip')) ;
    let t = Arp_handler.remove t ip' in
    Alcotest.(check (option m) "static entry is no longer in cache" None
                (Arp_handler.in_cache t ip'))

  let static_alias_good () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~ipaddr mac in
    let ip' = gen_ip () in
    let mac' = gen_mac () in
    let t, _ = Arp_handler.static t ip' mac' in
    Alcotest.(check (option m) "own entry is in cache" (Some mac)
                (Arp_handler.in_cache t ipaddr)) ;
    Alcotest.(check (option m) "static entry is in cache" (Some mac')
                (Arp_handler.in_cache t ip')) ;
    let t, _, _ = Arp_handler.alias t ip' in
    Alcotest.(check (option m) "alias entry overwrote static one" (Some mac)
                (Arp_handler.in_cache t ip')) ;
    let t, _ = Arp_handler.static t ip' mac' in
    Alcotest.(check (option m) "static entry overwrite aliased one" (Some mac')
                (Arp_handler.in_cache t ip')) ;
    let t = Arp_handler.remove t ip' in
    Alcotest.(check (option m) "static entry is no longer in cache" None
                (Arp_handler.in_cache t ip'))

  let more_good () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~ipaddr mac in
    let rec more_entries acc t = function
      | 0 -> acc, t
      | n ->
        let ip' = gen_ip () in
        if List.mem ip' (List.map fst acc) then
          more_entries acc t n
        else
          let t, e =
            if n mod 2 = 0 then
              let mac' = gen_mac () in
              let t, _ = Arp_handler.static t ip' mac' in
              (t, (ip', mac'))
            else
              let t, _, _ = Arp_handler.alias t ip' in
              (t, (ip', mac))
          in
          more_entries (e::acc) t (pred n)
    in
    let acc, t = more_entries [(ipaddr,mac)] t 100 in
    List.iter (fun (ip, mac) ->
        Alcotest.(check (option m) "entry is in cache" (Some mac)
                    (Arp_handler.in_cache t ip)))
      acc ;
    List.iter (fun (ip, _) ->
        let t = Arp_handler.remove t ip in
        Alcotest.(check (option m) "entry is no longer in cache" None
                    (Arp_handler.in_cache t ip)))
      acc ;
    let t = List.fold_left (fun t (ip, _) -> Arp_handler.remove t ip) t acc in
    Alcotest.(check (option m) "own entry is no longer in cache" None
                (Arp_handler.in_cache t ipaddr))

  let packet =
    let module M = struct
      type t = Arp_packet.t
      let pp = Arp_packet.pp
      let equal = Arp_packet.equal
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let out =
    let module M = struct
      type t = Arp_packet.t * Macaddr.t
      let pp ppf (cs, mac) =
        Format.fprintf ppf "out: %a to %a" Arp_packet.pp cs Macaddr.pp mac
      let equal (acs, amac) (bcs, bmac) =
        Arp_packet.equal acs bcs && Macaddr.compare amac bmac = 0
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let qres =
    let module M = struct
      type t = int list Arp_handler.qres
      let pp ppf = function
        | Arp_handler.Mac mac -> Format.fprintf ppf "ok %a" Macaddr.pp mac
        | Arp_handler.RequestWait ((cs, mac), xs) ->
          Format.fprintf ppf "requestwait %a to %a, wait %s"
            Arp_packet.pp cs Macaddr.pp mac
            (String.concat ", " (List.map string_of_int xs))
        | Arp_handler.Wait xs ->
          Format.fprintf ppf "wait %s"
            (String.concat ", " (List.map string_of_int xs))
      let equal a b = match a, b with
        | Arp_handler.Mac a, Arp_handler.Mac b -> Macaddr.compare a b = 0
        | Arp_handler.RequestWait ((csa, maca), xsa),
          Arp_handler.RequestWait ((csb, macb), xsb) ->
          Arp_packet.equal csa csb && Macaddr.compare maca macb = 0 &&
          List.length xsa = List.length xsb &&
          List.for_all (fun x -> List.mem x xsb) xsa
        | Arp_handler.Wait xsa, Arp_handler.Wait xsb ->
          List.length xsa = List.length xsb &&
          List.for_all (fun x -> List.mem x xsb) xsa
        |  _ -> false
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let merge v = function
    | None -> [v]
    | Some xs -> v::xs

  let handle_good () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~ipaddr mac in
    let _t, res = Arp_handler.query t ipaddr (merge 1) in
    Alcotest.check qres "own IP can be queried" (Arp_handler.Mac mac) res

  let query source_mac source_ip target_ip =
    { Arp_packet.operation = Arp_packet.Request ;
      source_mac ; source_ip ;
      target_mac = Macaddr.broadcast ; target_ip },
    Macaddr.broadcast

  let handle_gen_request () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~retries:1 ~ipaddr mac in
    let other = gen_ip () in
    let _, res = Arp_handler.query t other (merge 1) in
    let out = query mac ipaddr other in
    Alcotest.check qres "res is requestwait" (Arp_handler.RequestWait (out, [1])) res

  let handle_gen_request_twice () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~ipaddr ~retries:1 mac in
    let other = gen_ip () in
    let t, res = Arp_handler.query t other (merge 1) in
    let out = query mac ipaddr other in
    Alcotest.check qres "res is requestwait" (Arp_handler.RequestWait (out, [1])) res ;
    let _, res = Arp_handler.query t other (merge 2) in
    Alcotest.check qres "res is wait" (Arp_handler.Wait [2;1]) res

  let alias_wakes () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~ipaddr mac in
    let other = gen_ip () in
    let t, res = Arp_handler.query t other (merge 1) in
    let out = query mac ipaddr other in
    Alcotest.check qres "res is requestwait!" (Arp_handler.RequestWait (out, [1])) res ;
    Alcotest.(check (option m) "query is not cache" None (Arp_handler.in_cache t other)) ;
    let _, _, a = Arp_handler.alias t other in
    Alcotest.(check (option (list int)) "alias wakes up" (Some [1]) a)

  let static_wakes () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~ipaddr mac in
    let other = gen_ip () in
    let t, res = Arp_handler.query t other (merge 1) in
    let out = query mac ipaddr other in
    Alcotest.check qres "res is requestwait" (Arp_handler.RequestWait (out, [1])) res ;
    let _, a = Arp_handler.static t other mac in
    Alcotest.(check (option (list int)) "alias wakes up" (Some [1]) a)

  let handle_timeout () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~retries:1 ~ipaddr mac in
    let other = gen_ip () in
    let t, _ = Arp_handler.query t other (merge 1) in
    let t, _, a = Arp_handler.tick t in
    Alcotest.(check (list (list int)) "tick didn't timeout" [] a) ;
    let _, _, a = Arp_handler.tick t in
    Alcotest.(check (list (list int)) "tick timed out" [[1]] a)

  let req_before_timeout () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~timeout:1 ~ipaddr mac in
    let other = gen_ip () in
    let t, _ = Arp_handler.query t other (merge 1) in
    let omac = gen_mac () in
    let pkt =
      Arp_packet.encode { Arp_packet.operation = Arp_packet.Reply ;
                          source_ip = other ; source_mac = omac ;
                          target_ip = ipaddr ; target_mac = mac }
    in
    let t, outp, wake = Arp_handler.input t pkt in
    Alcotest.(check (option out) "out is none" None outp) ;
    Alcotest.(check (option (pair m (list int))) "wake is correct"
                (Some (omac, [1])) wake) ;
    let _, outp, rs = Arp_handler.tick t in
    Alcotest.(check bool "timeouts are empty" true (rs = [])) ;
    Alcotest.(check (list out) "arp request is sent" [query mac ipaddr other] outp)

  let multiple_reqs () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~retries:1 ~ipaddr mac in
    let other = gen_ip () in
    let t, res = Arp_handler.query t other (merge 1) in
    let q = query mac ipaddr other in
    Alcotest.check qres "query generates ARP request" (Arp_handler.RequestWait (q, [1])) res ;
    let t, outs, touts = Arp_handler.tick t in
    Alcotest.(check (list out) "tick generates second ARP request" [q] outs) ;
    Alcotest.(check (list (list int)) "tick generated no timeout yet" [] touts) ;
    let _, outs, touts = Arp_handler.tick t in
    Alcotest.(check (list out) "tick generated no other request" [] outs) ;
    Alcotest.(check (list (list int)) "tick generated a timeout" [[1]] touts)

  let multiple_reqs_2 () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~retries:4 ~ipaddr mac in
    let other = gen_ip () in
    let t, res = Arp_handler.query t other (merge 1) in
    let q = query mac ipaddr other in
    Alcotest.check qres "query generates ARP request" (Arp_handler.RequestWait (q, [1])) res ;
    let t, outs, touts = Arp_handler.tick t in
    Alcotest.(check (list out) "tick generates second ARP request" [q] outs) ;
    Alcotest.(check (list (list int)) "tick generated no timeout yet" [] touts) ;
    let t, outs, touts = Arp_handler.tick t in
    Alcotest.(check (list out) "tick generates third ARP request" [q] outs) ;
    Alcotest.(check (list (list int)) "tick generated no timeout yet" [] touts) ;
    let t, outs, touts = Arp_handler.tick t in
    Alcotest.(check (list out) "tick generates fourth ARP request" [q] outs) ;
    Alcotest.(check (list (list int)) "tick generated no timeout yet" [] touts) ;
    let t, outs, touts = Arp_handler.tick t in
    Alcotest.(check (list out) "tick generates fifth ARP request" [q] outs) ;
    Alcotest.(check (list (list int)) "tick generated no timeout yet" [] touts) ;
    let _, outs, touts = Arp_handler.tick t in
    Alcotest.(check (list out) "tick generated no other request" [] outs) ;
    Alcotest.(check (list (list int)) "tick generated a timeout" [[1]] touts)

  let handle_reply () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~timeout:1 ~ipaddr mac in
    let other = gen_ip () in
    let omac = gen_mac () in
    let pkt =
      Arp_packet.encode { Arp_packet.operation = Arp_packet.Reply ;
                          source_ip = other ; source_mac = omac ;
                          target_ip = ipaddr ; target_mac = mac }
    in
    let t, outp, w = Arp_handler.input t pkt in
    Alcotest.(check (option out) "nothing to be sent" None outp) ;
    Alcotest.(check (option (pair m (list int))) "noone wakes up" None w) ;
    Alcotest.(check (option m) "received entry is not in cache" None
                (Arp_handler.in_cache t other))

  let handle_garp () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~timeout:1 ~ipaddr mac in
    let other = gen_ip () in
    let omac = gen_mac () in
    let pkt = Arp_packet.encode (garp_of other omac) in
    let t, outp, w = Arp_handler.input t pkt in
    Alcotest.(check (option out) "nothing out" None outp) ;
    Alcotest.(check (option (pair m (list int))) "nothin woken up" None w) ;
    Alcotest.(check (option m) "received garp entry is not in cache" None
                (Arp_handler.in_cache t other))

  let answer_req_broadcast () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~timeout:1 ~ipaddr mac in
    let other = gen_ip () in
    let omac = gen_mac () in
    let pkt, _ = query omac other ipaddr in
    let _, outp, w = Arp_handler.input t (Arp_packet.encode pkt) in
    Alcotest.(check (option (pair m (list int))) "nothin woken up" None w) ;
    Alcotest.(check (option out) "request to us provokes a reply"
                (Some ({ Arp_packet.operation = Arp_packet.Reply ;
                         source_mac = mac ; source_ip = ipaddr ;
                         target_mac = omac ; target_ip = other },
                       omac)) outp)

  let answer_req_unicast () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~timeout:1 ~ipaddr mac in
    let other = gen_ip () in
    let omac = gen_mac () in
    let pkt =
      Arp_packet.encode { Arp_packet.operation = Arp_packet.Request ;
                          source_ip = other ; source_mac = omac ;
                          target_ip = ipaddr ; target_mac = mac }
    in
    let _, outp, w = Arp_handler.input t pkt in
    Alcotest.(check (option (pair m (list int))) "nothin woken up" None w) ;
    Alcotest.(check (option out) "request to us provokes a reply"
                (Some ({ Arp_packet.operation = Arp_packet.Reply ;
                         source_mac = mac ; source_ip = ipaddr ;
                         target_mac = omac ; target_ip = other },
                       omac)) outp)

  let not_answer_req () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~timeout:1 ~ipaddr mac in
    let other = gen_ip () in
    let third = gen_ip () in
    let omac = gen_mac () in
    let pkt, _ = query omac other third in
    let _, outp, w = Arp_handler.input t (Arp_packet.encode pkt) in
    Alcotest.(check (option out) "nothing out" None outp) ;
    Alcotest.(check (option (pair m (list int))) "nothin woken up" None w)

  let ignoring_random () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~timeout:1 ~ipaddr mac in
    let pkt = generate 24 in
    let _, outp, w = Arp_handler.input t pkt in
    Alcotest.(check (option out) "nothing out" None outp) ;
    Alcotest.(check (option (pair m (list int))) "nothin woken up" None w)

  let reply_does_not_override () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~timeout:1 ~ipaddr mac in
    let omac = gen_mac () in
    let pkt =
      Arp_packet.encode { Arp_packet.operation = Arp_packet.Reply ;
                          source_ip = ipaddr ; source_mac = omac ;
                          target_ip = ipaddr ; target_mac = mac }
    in
    let t, outp, w = Arp_handler.input t pkt in
    Alcotest.(check (option out) "nothing out" None outp) ;
    Alcotest.(check (option (pair m (list int))) "nothin woken up" None w) ;
    Alcotest.(check (option m) "our entry is still in cache" (Some mac)
                (Arp_handler.in_cache t ipaddr))

  let reply_query () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~timeout:1 ~ipaddr mac in
    let other = gen_ip () in
    let omac = gen_mac () in
    let pkt =
      Arp_packet.encode { Arp_packet.operation = Arp_packet.Reply ;
                          source_ip = other ; source_mac = omac ;
                          target_ip = ipaddr ; target_mac = mac }
    in
    let q = query mac ipaddr other in
    let t, r = Arp_handler.query t other (merge 1) in
    Alcotest.check qres "r is request wait" (Arp_handler.RequestWait (q, [1])) r ;
    let t, outp, w = Arp_handler.input t pkt in
    Alcotest.(check (option out) "nothing out" None outp) ;
    Alcotest.(check (option (pair m (list int))) "something woken up" (Some (omac, [1])) w) ;
    let _t, res = Arp_handler.query t other (merge 2) in
    Alcotest.check qres "dynamic entry can be queried" (Arp_handler.Mac omac) res

  let reply_in_cache () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~timeout:1 ~ipaddr mac in
    let other = gen_ip () in
    let omac = gen_mac () in
    let pkt =
      Arp_packet.encode { Arp_packet.operation = Arp_packet.Reply ;
                          source_ip = other ; source_mac = omac ;
                          target_ip = ipaddr ; target_mac = mac }
    in
    let q = query mac ipaddr other in
    let t, r = Arp_handler.query t other (merge 1) in
    Alcotest.check qres "r is request wait" (Arp_handler.RequestWait (q, [1])) r ;
    let t, outp, w = Arp_handler.input t pkt in
    Alcotest.(check (option out) "nothing out" None outp) ;
    Alcotest.(check (option (pair m (list int))) "something woken up" (Some (omac, [1])) w) ;
    Alcotest.(check (option m) "entry in cache" (Some omac) (Arp_handler.in_cache t other)) ;
    Alcotest.(check (list i) "ips do not include dynamic entries" [ipaddr] (Arp_handler.ips t))


  let reply_overriden () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~timeout:1 ~ipaddr mac in
    let other = gen_ip () in
    let omac = gen_mac () in
    let pkt =
      Arp_packet.encode { Arp_packet.operation = Arp_packet.Reply ;
                          source_ip = other ; source_mac = omac ;
                          target_ip = ipaddr ; target_mac = mac }
    in
    let q = query mac ipaddr other in
    let t, r = Arp_handler.query t other (merge 1) in
    Alcotest.check qres "r is request wait" (Arp_handler.RequestWait (q, [1])) r ;
    let t, outp, w = Arp_handler.input t pkt in
    Alcotest.(check (option out) "nothing out" None outp) ;
    Alcotest.(check (option (pair m (list int))) "something woken up" (Some (omac, [1])) w) ;
    Alcotest.(check (option m) "entry in cache" (Some omac) (Arp_handler.in_cache t other)) ;
    let t, outp, w = Arp_handler.input t pkt in
    Alcotest.(check (option out) "nothing out" None outp) ;
    Alcotest.(check (option (pair m (list int))) "nothing woken up" None w) ;
    Alcotest.(check (option m) "entry in cache" (Some omac) (Arp_handler.in_cache t other))

  let reply_overriden_other () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~timeout:1 ~ipaddr mac in
    let other = gen_ip () in
    let omac = gen_mac () in
    let pkt =
      Arp_packet.encode { Arp_packet.operation = Arp_packet.Reply ;
                          source_ip = other ; source_mac = omac ;
                          target_ip = ipaddr ; target_mac = mac }
    in
    let q = query mac ipaddr other in
    let t, r = Arp_handler.query t other (merge 1) in
    Alcotest.check qres "r is request wait" (Arp_handler.RequestWait (q, [1])) r ;
    let t, outp, w = Arp_handler.input t pkt in
    Alcotest.(check (option out) "nothing out" None outp) ;
    Alcotest.(check (option (pair m (list int))) "something woken up" (Some (omac, [1])) w) ;
    Alcotest.(check (option m) "entry in cache" (Some omac) (Arp_handler.in_cache t other)) ;
    let omac = gen_mac () in
    let pkt =
      Arp_packet.encode { Arp_packet.operation = Arp_packet.Reply ;
                          source_ip = other ; source_mac = omac ;
                          target_ip = ipaddr ; target_mac = mac }
    in
    let t, outp, w = Arp_handler.input t pkt in
    Alcotest.(check (option out) "nothing out" None outp) ;
    Alcotest.(check (option (pair m (list int))) "nothing woken up" None w) ;
    Alcotest.(check (option m) "overriden entry in cache" (Some omac)
                (Arp_handler.in_cache t other))

  let reply_times_out () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~timeout:1 ~ipaddr mac in
    let other = gen_ip () in
    let omac = gen_mac () in
    let pkt =
      Arp_packet.encode { Arp_packet.operation = Arp_packet.Reply ;
                          source_ip = other ; source_mac = omac ;
                          target_ip = ipaddr ; target_mac = mac }
    in
    let q = query mac ipaddr other in
    let t, r = Arp_handler.query t other (merge 1) in
    Alcotest.check qres "r is request wait" (Arp_handler.RequestWait (q, [1])) r ;
    let t, outp, w = Arp_handler.input t pkt in
    Alcotest.(check (option out) "nothing out" None outp) ;
    Alcotest.(check (option (pair m (list int))) "something woken up" (Some (omac, [1])) w) ;
    Alcotest.(check (option m) "entry in cache" (Some omac) (Arp_handler.in_cache t other)) ;
    let t, outp, timeout = Arp_handler.tick t in
    Alcotest.(check (list out) "request sent" [q] outp) ;
    Alcotest.(check (list (list int)) "nothing timed out" [] timeout) ;
    let t, outp, timeout = Arp_handler.tick t in
    Alcotest.(check (list out) "nada sent" [] outp) ;
    Alcotest.(check (list (list int)) "nothing timed out" [] timeout) ;
    Alcotest.(check (option m) "entry no longer in cache" None
                (Arp_handler.in_cache t other))

  let dyn_not_advertised () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~timeout:1 ~ipaddr mac in
    let other = gen_ip () in
    let omac = gen_mac () in
    let pkt =
      Arp_packet.encode { Arp_packet.operation = Arp_packet.Reply ;
                          source_ip = other ; source_mac = omac ;
                          target_ip = ipaddr ; target_mac = mac }
    in
    let q = query mac ipaddr other in
    let t, r = Arp_handler.query t other (merge 1) in
    Alcotest.check qres "r is request wait" (Arp_handler.RequestWait (q, [1])) r ;
    let t, outp, w = Arp_handler.input t pkt in
    Alcotest.(check (option out) "nothing out" None outp) ;
    Alcotest.(check (option (pair m (list int))) "something woken up" (Some (omac, [1])) w) ;
    let third = gen_ip ()
    and third_mac = gen_mac ()
    in
    let q, _ = query third_mac third other in
    let _, outp, w = Arp_handler.input t (Arp_packet.encode q) in
    Alcotest.(check (option out) "request a dynamic entry is not answered" None outp) ;
    Alcotest.(check (option (pair m (list int))) "nothing woken up" None w)

  let handle_reply_wakesup () =
    let mac = gen_mac ()
    and ipaddr = gen_ip ()
    in
    let t, _garp = Arp_handler.create ~timeout:1 ~ipaddr mac in
    let other = gen_ip () in
    let omac = gen_mac () in
    let pkt =
      Arp_packet.encode { Arp_packet.operation = Arp_packet.Reply ;
                          source_ip = other ; source_mac = omac ;
                          target_ip = ipaddr ; target_mac = mac }
    in
    let q = query mac ipaddr other in
    let t, r = Arp_handler.query t other (merge 1) in
    Alcotest.check qres "r is request wait" (Arp_handler.RequestWait (q, [1])) r ;
    let t, r = Arp_handler.query t other (merge 2) in
    Alcotest.check qres "r is wait" (Arp_handler.Wait [2;1]) r ;
    let _, outp, w = Arp_handler.input t pkt in
    Alcotest.(check (option out) "nothing out" None outp) ;
    Alcotest.(check (option (pair m (list int))) "something woken up" (Some (omac, [2;1])) w)

  let handl_tsts = [
    "create raises", `Quick, create_raises ;
    "basic tests", `Quick, basic_good ;
    "remove test", `Quick, remove_good ;
    "remove no test", `Quick, remove_no ;
    "alias test", `Quick, alias_good ;
    "alias remove test", `Quick, alias_remove_inverse ;
    "static test", `Quick, static_good ;
    "static alias test", `Quick, static_alias_good ;
    "more tests", `Quick, more_good ;
    "handle good", `Quick, handle_good ;
    "handle generates req", `Quick, handle_gen_request ;
    "handle generates req, next doesn't", `Quick, handle_gen_request_twice ;
    "alias wakes", `Quick, alias_wakes ;
    "static wakes", `Quick, static_wakes ;
    "handle timeout", `Quick, handle_timeout ;
    "request send before timeout", `Quick, req_before_timeout ;
    "multiple requests are send", `Quick, multiple_reqs ;
    "multiple requests are send 2", `Quick, multiple_reqs_2 ;
    "handle reply", `Quick, handle_reply ;
    "handle garp", `Quick, handle_garp ;
    "answers broadcast request", `Quick, answer_req_broadcast ;
    "answers unicast request", `Quick, answer_req_unicast ;
    "not answering random request", `Quick, not_answer_req ;
    "ignoring random", `Quick, ignoring_random ;
    "reply does not harm static entries", `Quick, reply_does_not_override ;
    "reply is in cache", `Quick, reply_in_cache ;
    "dynamic entry can be queried", `Quick, reply_query ;
    "reply times out", `Quick, reply_times_out ;
    "dynamic entry overriden by same", `Quick, reply_overriden ;
    "dynamic entry overriden by other", `Quick, reply_overriden_other ;
    "dynamic entry is not advertised", `Quick, dyn_not_advertised ;
    "reply wakes tasks", `Quick, handle_reply_wakesup ;
  ]
end

let tests = [
  "Coder", Coding.coder_tsts ;
  "Handler", Handling.handl_tsts ;
]

let () =
  Random.self_init ();
  Alcotest.run "ARP tests" tests
