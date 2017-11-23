(* based on ISC-licensed mirage-tcpip module *)
type t = {
  operation : Arp_wire.op;
  source_mac : Macaddr.t;
  source_ip : Ipaddr.V4.t;
  target_mac : Macaddr.t;
  target_ip : Ipaddr.V4.t;
}

type error =
  | Too_short
  | Unusable
  | Unknown_operation of Cstruct.uint16

(*BISECT-IGNORE-BEGIN*)
let pp fmt t =
  if t.operation = Arp_wire.Request then
    Format.fprintf fmt "ARP request, who has %a tell %a"
      Ipaddr.V4.pp_hum t.target_ip Ipaddr.V4.pp_hum t.source_ip
  else (* t.op = Arp_wire.Reply *)
    Format.fprintf fmt "ARP reply, %a is at %s"
      Ipaddr.V4.pp_hum t.source_ip (Macaddr.to_string t.source_mac)

let pp_error ppf = function
  | Too_short -> Format.pp_print_string ppf "frame too short (below 28 bytes)"
  | Unusable -> Format.pp_print_string ppf "ARP address types are not IPv4 and Ethernet"
  | Unknown_operation i -> Format.fprintf ppf "ARP message has unsupported operation %d" i
(*BISECT-IGNORE-END*)

(* may be defined elsewhere *)
let ipv4_ethertype = 0x0800
and ipv4_size = 4
and ether_htype = 1
and ether_size = 6

let guard p e = if p then Ok () else Error e

let (>>=) x f = match x with
  | Ok y -> f y
  | Error e -> Error e

let decode buf =
  let open Arp_wire in
  let check_len buf = Cstruct.len buf >= sizeof_arp in
  let check_hdr buf =
    get_arp_htype buf = ether_htype &&
    get_arp_ptype buf = ipv4_ethertype &&
    get_arp_hlen buf = ether_size &&
    get_arp_plen buf = ipv4_size
  in
  guard (check_len buf) Too_short >>= fun () ->
  guard (check_hdr buf) Unusable >>= fun () ->
  match Arp_wire.int_to_op @@ get_arp_op buf with
  | None -> Error (Unknown_operation (get_arp_op buf))
  | Some operation ->
    let source_mac = Macaddr.of_bytes_exn (copy_arp_sha buf)
    and target_mac = Macaddr.of_bytes_exn (copy_arp_tha buf)
    and source_ip = Ipaddr.V4.of_int32 (get_arp_spa buf)
    and target_ip = Ipaddr.V4.of_int32 (get_arp_tpa buf)
    in
    Ok {
      operation ;
      source_mac; source_ip ;
      target_mac; target_ip
    }

let hdr =
  let buf = Cstruct.create 6 in
  let open Arp_wire in
  set_arp_htype buf ether_htype;
  set_arp_ptype buf ipv4_ethertype;
  set_arp_hlen buf ether_size;
  set_arp_plen buf ipv4_size;
  buf

let encode_into t buf =
  let open Arp_wire in
  Cstruct.blit hdr 0 buf 0 6 ;
  set_arp_op buf (op_to_int t.operation);
  set_arp_sha (Macaddr.to_bytes t.source_mac) 0 buf;
  set_arp_spa buf (Ipaddr.V4.to_int32 t.source_ip);
  set_arp_tha (Macaddr.to_bytes t.target_mac) 0 buf;
  set_arp_tpa buf (Ipaddr.V4.to_int32 t.target_ip)
  [@@inline]

let encode t =
  let buf = Cstruct.create_unsafe Arp_wire.sizeof_arp in
  encode_into t buf;
  buf
