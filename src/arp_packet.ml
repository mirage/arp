(* based on ISC-licensed mirage-tcpip module *)

type op =
  | Request
  | Reply

let op_to_int = function Request -> 1 | Reply -> 2
let int_to_op = function 1 -> Some Request | 2 -> Some Reply | _ -> None

(* ARP packet contains:
   16 bit hardware type = ethernet = 0x01
   16 bit protocol type = ipv4 = 0x0800
   8 bit hardware address length = 6
   8 bit protocol address length = 4
   16 bit operation
   sender hardware address = 6 byte
   sender protocol address = 4 byte
   target hardware address = 6 byte
   target protocol address = 4 byte
 *)

type t = {
  operation : op;
  source_mac : Macaddr.t;
  source_ip : Ipaddr.V4.t;
  target_mac : Macaddr.t;
  target_ip : Ipaddr.V4.t;
}

let equal a b =
  op_to_int a.operation = op_to_int b.operation &&
  Macaddr.compare a.source_mac b.source_mac = 0 &&
  Ipaddr.V4.compare a.source_ip b.source_ip = 0 &&
  Macaddr.compare a.target_mac b.target_mac = 0 &&
  Ipaddr.V4.compare a.target_ip b.target_ip = 0

type error =
  | Too_short
  | Unusable
  | Unknown_operation of Cstruct.uint16

(*BISECT-IGNORE-BEGIN*)
let pp fmt t =
  if t.operation = Request then
    Format.fprintf fmt "ARP request from %a to %a, who has %a tell %a"
      Macaddr.pp t.source_mac Macaddr.pp t.target_mac
      Ipaddr.V4.pp t.target_ip Ipaddr.V4.pp t.source_ip
  else (* t.op = Reply *)
    Format.fprintf fmt "ARP reply from %a to %a, %a is at %a"
      Macaddr.pp t.source_mac Macaddr.pp t.target_mac
      Ipaddr.V4.pp t.source_ip Macaddr.pp t.source_mac

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
and size = 28

let guard p e = if p then Ok () else Error e

let (>>=) x f = match x with
  | Ok y -> f y
  | Error e -> Error e

let decode buf =
  let check_len buf = Cstruct.len buf >= size in
  let check_hdr buf =
    Cstruct.BE.get_uint16 buf 0 = ether_htype &&
    Cstruct.BE.get_uint16 buf 2 = ipv4_ethertype &&
    Cstruct.get_uint8 buf 4 = ether_size &&
    Cstruct.get_uint8 buf 5 = ipv4_size
  in
  guard (check_len buf) Too_short >>= fun () ->
  guard (check_hdr buf) Unusable >>= fun () ->
  let op = Cstruct.BE.get_uint16 buf 6 in
  match int_to_op op with
  | None -> Error (Unknown_operation op)
  | Some operation ->
    let source_mac = Macaddr.of_octets_exn (Cstruct.to_string (Cstruct.sub buf 8 6))
    and target_mac = Macaddr.of_octets_exn (Cstruct.to_string (Cstruct.sub buf 18 6))
    and source_ip = Ipaddr.V4.of_int32 (Cstruct.BE.get_uint32 buf 14)
    and target_ip = Ipaddr.V4.of_int32 (Cstruct.BE.get_uint32 buf 24) in
    Ok {
      operation ;
      source_mac; source_ip ;
      target_mac; target_ip
    }

let hdr =
  let buf = Cstruct.create 6 in
  Cstruct.BE.set_uint16 buf 0 ether_htype;
  Cstruct.BE.set_uint16 buf 2 ipv4_ethertype;
  Cstruct.set_uint8 buf 4 ether_size;
  Cstruct.set_uint8 buf 5 ipv4_size;
  buf

let encode_into t buf =
  Cstruct.blit hdr 0 buf 0 6 ;
  Cstruct.BE.set_uint16 buf 6 (op_to_int t.operation) ;
  Cstruct.blit_from_string (Macaddr.to_octets t.source_mac) 0 buf 8 6 ;
  Cstruct.BE.set_uint32 buf 14 (Ipaddr.V4.to_int32 t.source_ip) ;
  Cstruct.blit_from_string (Macaddr.to_octets t.target_mac) 0 buf 18 6 ;
  Cstruct.BE.set_uint32 buf 24 (Ipaddr.V4.to_int32 t.target_ip)
  [@@inline]

let encode t =
  let buf = Cstruct.create_unsafe size in
  encode_into t buf;
  buf
