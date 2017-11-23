(** Conversion between wire and high-level data

    There is a {{!Arp_wire}binary wire representation}, and a {{!t}high-level
    datatype}.  This module converts between the two.  While decoding can result
    in an error, encoding can not.
*)

(** The high-level ARP frame consisting of the two address pairs and an operation. *)
type t = {
  operation : Arp_wire.op;
  source_mac : Macaddr.t;
  source_ip : Ipaddr.V4.t;
  target_mac : Macaddr.t;
  target_ip : Ipaddr.V4.t;
}

(** [pp ppf t] prints the frame [t] on [ppf]. *)
val pp : Format.formatter -> t -> unit

(** The type of possible errors during decoding

    - [Too_short] if the provided buffer is not long enough
    - [Unusable] if the protocol or hardware address type is not IPv4 and Ethernet
    - [Unknown_operation] if it is neither a request nor a reply
  *)
type error =
  | Too_short
  | Unusable
  | Unknown_operation of Cstruct.uint16

(** [pp_error ppf err] prints the error [err] on [ppf]. *)
val pp_error : Format.formatter -> error -> unit

(** {2 Decoding} *)

(** [decode buf] attempts to decode the buffer into an ARP frame [t]. *)
val decode : Cstruct.t -> (t, error) result

(** {2 Encoding} *)

(** [encode t] is a [buf], a freshly allocated buffer, which contains the
    encoded ARP frame [t]. *)
val encode : t -> Cstruct.t

(** [encode_into t buf] encodes [t] into the buffer [buf] at offset 0.

    @raise Invalid_argument if the buffer [buf] is too small (below 28 bytes). *)
val encode_into : t -> Cstruct.t -> unit
