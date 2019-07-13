
type 'a entry =
  | Static of Macaddr.t * bool
  | Dynamic of Macaddr.t * int
  | Pending of 'a * int

module M = Map.Make(Ipaddr.V4)

type 'a t = {
  cache : 'a entry M.t ;
  mac : Macaddr.t ;
  ip : Ipaddr.V4.t ;
  timeout : int ;
  retries : int ;
  epoch : int ;
  logsrc : Logs.src
}

let ips t =
  M.fold (fun ip entry acc -> match entry with
      | Static (_, true) -> ip :: acc
      | _ -> acc)
    t.cache []

let mac t = t.mac

(*BISECT-IGNORE-BEGIN*)
let pp_entry now k pp =
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

let pp pp t =
  Format.fprintf pp "mac %a ip %a entries %d timeout %d retries %d@."
    Macaddr.pp t.mac
    Ipaddr.V4.pp t.ip
    (M.cardinal t.cache)
    t.timeout t.retries ;
  M.iter (fun k v -> pp_entry t.epoch k pp v ; Format.pp_print_space pp ()) t.cache
(*BISECT-IGNORE-END*)

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
  (*BISECT-IGNORE-BEGIN*)
  Logs.info ~src:t.logsrc
    (fun pp -> pp "Sending gratuitous ARP for %a (%a)"
        Ipaddr.V4.pp ip Macaddr.pp t.mac) ;
  (*BISECT-IGNORE-END*)
  { t with cache }, (garp, Macaddr.broadcast), pending t ip

let create ?(timeout = 800) ?(retries = 5)
    ?(logsrc = Logs.Src.create "arp" ~doc:"ARP handler")
    ?ipaddr
    mac =
  if timeout <= 0 then
    invalid_arg "timeout must be strictly positive" ;
  if retries < 0 then
    invalid_arg "retries must be positive" ;
  let cache = M.empty in
  let ip = match ipaddr with None -> Ipaddr.V4.any | Some x -> x in
  let t = { cache ; mac ; ip ; timeout ; retries ; epoch = 0 ; logsrc } in
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

let request t ip =
  let target = Macaddr.broadcast in
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
  let entry k v (cache, acc, r) = match v with
    | Dynamic (m, tick) when tick = epoch ->
      (*BISECT-IGNORE-BEGIN*)
      Logs.debug ~src:t.logsrc
        (fun pp -> pp "removing ARP entry %a (mac %a)"
            Ipaddr.V4.pp k Macaddr.pp m) ;
      (*BISECT-IGNORE-END*)
      M.remove k cache, acc, r
    | Dynamic (_, tick) when tick = succ epoch ->
      cache, request t k :: acc, r
    | Pending (a, retry) when retry = epoch ->
      (*BISECT-IGNORE-BEGIN*)
      Logs.info ~src:t.logsrc
        (fun pp -> pp "ARP timeout after %d retries for %a"
            t.retries Ipaddr.V4.pp k) ;
      (*BISECT-IGNORE-END*)
      M.remove k cache, acc, a :: r
    | Pending _ -> cache, request t k :: acc, r
    | _ -> cache, acc, r
  in
  let cache, outs, r = M.fold entry t.cache (t.cache, [], []) in
  { t with cache ; epoch = succ epoch }, outs, r

let handle_reply t source mac =
  let extcache =
    let cache = M.add source (Dynamic (mac, t.epoch + t.timeout)) t.cache in
    { t with cache }
  in
  match M.find source t.cache with
  | exception Not_found ->
    t, None, None
  | Static (_, adv) ->
    if adv && Macaddr.compare mac mac0 = 0 then
      (*BISECT-IGNORE-BEGIN*)
      Logs.info ~src:t.logsrc
        (fun pp ->
           pp "ignoring gratuitous ARP from %a using my IP address %a"
             Macaddr.pp mac Ipaddr.V4.pp source)
      (*BISECT-IGNORE-END*)
    else
      (*BISECT-IGNORE-BEGIN*)
      Logs.info ~src:t.logsrc
        (fun pp ->
           pp "ignoring ARP reply for %a (static %sarp entry in cache)"
             Ipaddr.V4.pp source (if adv then "advertised " else "")) ;
      (*BISECT-IGNORE-END*)
    t, None, None
  | Dynamic (m, _) ->
    if Macaddr.compare mac m <> 0 then
      (*BISECT-IGNORE-BEGIN*)
      Logs.warn ~src:t.logsrc
        (fun pp -> pp "ARP for %a moved from %a to %a"
            Ipaddr.V4.pp source
            Macaddr.pp m
            Macaddr.pp mac) ;
      (*BISECT-IGNORE-END*)
    extcache, None, None
  | Pending (xs, _) -> extcache, None, Some (mac, xs)


let handle_request t arp =
  let dest = arp.Arp_packet.target_ip
  and source = arp.Arp_packet.source_ip
  in
  match M.find dest t.cache with
  | exception Not_found ->
    (*BISECT-IGNORE-BEGIN*)
    Logs.debug ~src:t.logsrc
      (fun pp -> pp "ignoring ARP request for %a from %a (mac %a)"
          Ipaddr.V4.pp dest
          Ipaddr.V4.pp source
          Macaddr.pp arp.Arp_packet.source_mac) ;
    (*BISECT-IGNORE-END*)
    t, None, None
  | Static (m, true) ->
    (*BISECT-IGNORE-BEGIN*)
    Logs.debug ~src:t.logsrc
      (fun pp -> pp "replying to ARP request for %a from %a (mac %a)"
          Ipaddr.V4.pp dest
          Ipaddr.V4.pp source
          Macaddr.pp arp.Arp_packet.source_mac) ;
    (*BISECT-IGNORE-END*)
    t, Some (reply arp m), None
  | _ ->
    (*BISECT-IGNORE-BEGIN*)
    Logs.debug ~src:t.logsrc
      (fun pp -> pp "ignoring ARP request for %a from %a (mac %a)"
          Ipaddr.V4.pp dest
          Ipaddr.V4.pp source
          Macaddr.pp arp.Arp_packet.source_mac) ;
    (*BISECT-IGNORE-END*)
    t, None, None

let input t buf =
  match Arp_packet.decode buf with
  | Error e ->
    (*BISECT-IGNORE-BEGIN*)
    Logs.info ~src:t.logsrc
        (fun pp -> pp "Failed to parse ARP frame %a" Arp_packet.pp_error e) ;
    (*BISECT-IGNORE-END*)
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
    { t with cache }, RequestWait (request t ip, a)
  | Pending (x, r) ->
    let a = a (Some x) in
    let cache = M.add ip (Pending (a, r)) t.cache in
    { t with cache }, Wait a
  | Static (m, _) -> t, Mac m
  | Dynamic (m, _) -> t, Mac m
