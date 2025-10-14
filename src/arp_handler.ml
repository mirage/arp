
type 'a entry =
  | Static of Macaddr.t * bool
  | Dynamic of Macaddr.t * int (* active dynamic entry *)
  | Pending of 'a * int        (* unresolved pending entry *)
  | Stale of Macaddr.t * int   (* stale dynamic entry *)
  | Probing of Macaddr.t * int (* probing stale entry *)

module M = Map.Make(Ipaddr.V4)

type 'a t = {
  cache : 'a entry M.t ;
  mac : Macaddr.t ;
  ip : Ipaddr.V4.t ;
  timeout : int ; (* Stale entry expire interval in ticks *)
  refresh : int ; (* Dynamic entry becomes stale interval in ticks *)
  retries : int ; (* how many retries for ARP requests/probes *)
  epoch : int ;   (* current tick value *)
  logsrc : Logs.src
}

let ips t =
  M.fold (fun ip entry acc -> match entry with
      | Static (_, true) -> ip :: acc
      | _ -> acc)
    t.cache []

let mac t = t.mac

let[@coverage off] pp_entry now k pp =
  function
  | Static (m, adv) ->
    let adv = if adv then " advertising" else "" in
    Format.fprintf pp "%a at %a (static%s)" Ipaddr.V4.pp k Macaddr.pp m adv
  | Dynamic (m, t) ->
    Format.fprintf pp "%a at %a (timeout in %d)" Ipaddr.V4.pp k
      Macaddr.pp m (t - now)
  | Pending (_, retries) ->
    Format.fprintf pp "%a (incomplete, %d retries left)"
      Ipaddr.V4.pp k (retries - now)
  | Stale (m, t) ->
    Format.fprintf pp "%a at %a (stale, timeout in %d)" Ipaddr.V4.pp k
      Macaddr.pp m (t - now)
  | Probing (m, t) ->
    Format.fprintf pp "%a at %a (probing, timeout in %d)" Ipaddr.V4.pp k
      Macaddr.pp m (t - now)

let[@coverage off] pp pp t =
  Format.fprintf pp "mac %a ip %a entries %d timeout %d retries %d@."
    Macaddr.pp t.mac
    Ipaddr.V4.pp t.ip
    (M.cardinal t.cache)
    t.timeout t.retries ;
  M.iter (fun k v -> pp_entry t.epoch k pp v ; Format.pp_print_space pp ()) t.cache

let pending t ip =
  match M.find ip t.cache with
  | exception Not_found -> None
  | Pending (a, _) -> Some a
  | _ -> None

let mac0 = Macaddr.of_octets_exn (Cstruct.to_string (Cstruct.create 6))

let alias t ip =
  let cache = M.add ip (Static (t.mac, true)) t.cache in
  (* see RFC5227 Section 3 why we send out an ARP request *)
  let garp = Arp_packet.({
      operation = Request ;
      source_mac = t.mac ;
      target_mac = mac0 ;
      source_ip = ip ; target_ip = ip })
  in
  Logs.info ~src:t.logsrc
    (fun pp -> pp "Sending gratuitous ARP for %a (%a)"
        Ipaddr.V4.pp ip Macaddr.pp t.mac) ;
  { t with cache }, (garp, Macaddr.broadcast), pending t ip

let create ?(timeout = 800) ?(refresh = 40) ?(retries = 5)
    ?(logsrc = Logs.Src.create "arp" ~doc:"ARP handler")
    ?ipaddr
    mac =
  if timeout <= 0 then
    invalid_arg "timeout must be strictly positive" ;
  if retries < 0 then
    invalid_arg "retries must be positive" ;
  let cache = M.empty in
  let ip = match ipaddr with None -> Ipaddr.V4.any | Some x -> x in
  let t = { cache ; mac ; ip ; timeout ; refresh;  retries ; epoch = 0 ; logsrc } in
  match ipaddr with
  | None -> t, None
  | Some ip ->
    let t, garp, _ = alias t ip in
    t, Some garp

let static t ip mac =
  let cache = M.add ip (Static (mac, false)) t.cache in
  { t with cache }, pending t ip

let remove t ip =
  let cache = M.remove ip t.cache in
  { t with cache }

let in_cache t ip =
  match M.find ip t.cache with
  | exception Not_found -> None
  | Pending _ -> None
  | Static (m, _) -> Some m
  | Dynamic (m, _) -> Some m
  | Stale (m, _) -> Some m
  | Probing (m, _) -> Some m

let request t ?(target = Macaddr.broadcast) ip =
  let request = {
    Arp_packet.operation = Arp_packet.Request ;
    source_mac = t.mac ; source_ip = t.ip ;
    target_mac = target ; target_ip = ip
  }
  in
  request, target

let reply arp m =
  let reply = {
    Arp_packet.operation = Arp_packet.Reply ;
    source_mac = m ; source_ip = arp.Arp_packet.target_ip ;
    target_mac = arp.Arp_packet.source_mac ; target_ip = arp.Arp_packet.source_ip ;
  } in
  reply, arp.Arp_packet.source_mac

let tick t =
  let epoch = t.epoch in
  (* Logs.debug ~src:t.logsrc (fun pp -> pp "tick: %d" epoch) ; *)
  let entry k v (cache, acc, r) = match v with
    | Stale (m, tick) when tick = epoch ->
      Logs.debug ~src:t.logsrc
        (fun pp -> pp "removing stale ARP entry %a (mac %a)"
            Ipaddr.V4.pp k Macaddr.pp m) ;
      M.remove k cache, acc, r
    | Dynamic (m, tick) when tick = epoch ->
      Logs.debug ~src:t.logsrc
        (fun pp -> pp "ARP entry %a (mac %a) timed out --> Stale"
            Ipaddr.V4.pp k Macaddr.pp m) ;
      M.add k (Stale (m, t.epoch + t.timeout)) cache, acc, r
    | Pending (a, retry) when retry = epoch ->
      Logs.info ~src:t.logsrc
        (fun pp -> pp "ARP timeout after %d retries for %a"
            t.retries Ipaddr.V4.pp k) ;
      M.remove k cache, acc, a :: r
    | Pending (_, retry) ->
      Logs.debug ~src:t.logsrc
        (fun pp -> pp "resending ARP request for %a (%d left)"
            Ipaddr.V4.pp k (retry - epoch)) ;
      cache, request t k :: acc, r
    | Probing (m, retry) when retry = epoch ->
      Logs.info ~src:t.logsrc
        (fun pp -> pp "unicast ARP probe timeout after %d retries for %a/%a failed"
            t.retries Ipaddr.V4.pp k Macaddr.pp m) ;
      M.remove k cache, acc, r
    | Probing (target, retry) ->
      Logs.debug ~src:t.logsrc
        (fun pp -> pp "sending unicast ARP probe for %a/%a (%d left)"
            Ipaddr.V4.pp k Macaddr.pp target (retry - epoch)) ;
      cache, request t ~target k :: acc, r
    | _ -> cache, acc, r
  in
  let cache, outs, r = M.fold entry t.cache (t.cache, [], []) in
  { t with cache ; epoch = succ epoch }, outs, r

let handle_reply t source mac =
  let update_cache () =
    let cache = M.add source (Dynamic (mac, t.epoch + t.refresh)) t.cache in
    { t with cache }
  in
  match M.find source t.cache with
  | exception Not_found ->
    t, None, None
  | Static (_, adv) ->
    if adv && Macaddr.compare mac mac0 = 0 then
      Logs.info ~src:t.logsrc
        (fun pp ->
           pp "ignoring gratuitous ARP from %a using my IP address %a"
             Macaddr.pp mac Ipaddr.V4.pp source)[@coverage off]
    else
      Logs.info ~src:t.logsrc
        (fun pp ->
           pp "ignoring ARP reply for %a (static %sarp entry in cache)"
             Ipaddr.V4.pp source (if adv then "advertised " else ""))
      [@coverage off] ;
    t, None, None
  | Dynamic (m, _)
  | Stale (m, _)
  | Probing (m, _) ->
    let t = if Macaddr.compare mac m <> 0 then
      let cache = M.add source (Stale (mac, t.epoch + t.timeout)) t.cache in
      Logs.warn ~src:t.logsrc
        (fun pp -> pp "MAC address for %a moved from %a to %a, marked as stale"
            Ipaddr.V4.pp source
            Macaddr.pp m
            Macaddr.pp mac);
      { t with cache }
      else (
      Logs.debug ~src:t.logsrc
      (fun pp -> pp "ARP reply received for %a/%a, refreshing cache entry"
          Ipaddr.V4.pp source Macaddr.pp mac);
      update_cache ())
    in
    t, None, None
  | Pending (xs, _) ->
    Logs.debug ~src:t.logsrc
      (fun pp -> pp "ARP reply received for %a/%a, adding cache entry"
          Ipaddr.V4.pp source Macaddr.pp mac);
    update_cache (), None, Some (mac, xs)

let handle_request t arp =
  let dest = arp.Arp_packet.target_ip
  and source = arp.Arp_packet.source_ip
  in
  match M.find dest t.cache with
  | exception Not_found ->
    Logs.debug ~src:t.logsrc
      (fun pp -> pp "ignoring ARP request for %a from %a (mac %a)"
          Ipaddr.V4.pp dest
          Ipaddr.V4.pp source
          Macaddr.pp arp.Arp_packet.source_mac) ;
    t, None, None
  | Static (m, true) ->
    Logs.debug ~src:t.logsrc
      (fun pp -> pp "replying to ARP request for %a from %a (mac %a)"
          Ipaddr.V4.pp dest
          Ipaddr.V4.pp source
          Macaddr.pp arp.Arp_packet.source_mac) ;
    t, Some (reply arp m), None
  | _ ->
    Logs.debug ~src:t.logsrc
      (fun pp -> pp "ignoring ARP request for %a from %a (mac %a)"
          Ipaddr.V4.pp dest
          Ipaddr.V4.pp source
          Macaddr.pp arp.Arp_packet.source_mac)
    [@coverage off] ;
    t, None, None

let input t buf =
  match Arp_packet.decode buf with
  | Error e ->
    Logs.info ~src:t.logsrc
        (fun pp -> pp "Failed to parse ARP frame %a" Arp_packet.pp_error e) ;
    t, None, None
  | Ok arp ->
    if
      Ipaddr.V4.compare arp.Arp_packet.source_ip arp.Arp_packet.target_ip = 0 ||
      arp.Arp_packet.operation = Arp_packet.Reply
    then
      let mac = arp.Arp_packet.source_mac
      and source = arp.Arp_packet.source_ip
      in
      handle_reply t source mac
    else (* must be a request *)
      handle_request t arp

type 'a qres =
  | Mac of Macaddr.t
  | Wait of 'a
  | RequestWait of (Arp_packet.t * Macaddr.t) * 'a

let query t ip a =
  match M.find ip t.cache with
  | exception Not_found ->
    let a = a None in
    let cache = M.add ip (Pending (a, t.epoch + t.retries)) t.cache in
    Logs.debug ~src:t.logsrc
      (fun pp -> pp "sending ARP request for %a --> Pending"
          Ipaddr.V4.pp ip) ;
    { t with cache }, RequestWait (request t ip, a)
  | Pending (x, r) ->
    let a = a (Some x) in
    let cache = M.add ip (Pending (a, r)) t.cache in
    { t with cache }, Wait a
  | Stale (m, _) ->
    Logs.debug ~src:t.logsrc
      (fun pp -> pp "request for stale entry %a/%a --> Probing"
          Ipaddr.V4.pp ip Macaddr.pp m) ;
    let cache = M.add ip (Probing (m, t.epoch + t.retries)) t.cache in
    { t with cache }, Mac m
  | Static (m, _)
  | Dynamic (m, _)
  | Probing (m, _) -> t, Mac m
