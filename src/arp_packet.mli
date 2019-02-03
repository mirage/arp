(** Conversion between wire and high-level data

    The {{!t}high-level datatype} can be decoded and encoded to bytes to be sent
    on the wire.  ARP specifies hardware and protocol addresses, but this
    implementation picks Ethernet and IPv4 statically. While decoding can result
    in an error, encoding can not.  *)

type op =
  | Request
  | Reply

val op_to_int : op -> int
val int_to_op : int -> op option

(** The high-level ARP frame consisting of the two address pairs and an operation. *)
type t = {
  operation : op;
  source_mac : Macaddr.t;
  source_ip : Ipaddr.V4.t;
  target_mac : Macaddr.t;
  target_ip : Ipaddr.V4.t;
}

(** [size] is the size of an ARP frame. *)
val size : int

(** [pp ppf t] prints the frame [t] on [ppf]. *)
val pp : Format.formatter -> t -> unit

(** [equal a b] returns [true] if frames [a] and [b] are equal, [false] otherwise. *)
val equal : t -> t -> bool

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
