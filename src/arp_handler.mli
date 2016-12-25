(** Protocol handler for the Address Resolution Protocol

    This library provides a pure implementation of ARP, which handles only IPv4
    addresses as protocol and Ethernet (MAC) addresses as hardware.  This is the
    most common usage of ARP currently.  There is no support for other types of
    addresses.  ARP is initially specified in
    {{:https://tools.ietf.org/html/rfc826}, RFC826}, and further refined in
    {{:https://tools.ietf.org/html/rfc1122}, RFC1122} and partially
    {{:https://tools.ietf.org/html/rfc5227}, RFC5227}.

    The ARP handler consists of a cache, which maps IPv4 addresses to Ethernet
    addresses, and access to it.  Its configuration is set during
    {{!create}construction}, together with the own IPv4 address and Ethernet
    address.  The cache can be modified with {{!static}static} entries of other
    hosts, {{!alias}IPv4 aliases}, {{!remove}removal} of entries.  Outgoing
    frames always use its {{!ip}main IPv4 address}.  Whether an entry
    {{!in_cache}is available} or not can be inspected.

    The ARP handler can process {{!input}network input}, which may extend the
    cache with dynamic ARP entries which time out after the configured period.
    Periodic calls to {!tick} are required for the timeout and retry mechanisms.
    Since ARP usually uses network communication, callers may {!query} the cache
    and wait until either a response was received or a timeout occured after
    several retries.

    The embedded merge strategy is simple: static entries always win (and thus,
    both {!alias} and {!static} overwrite existing entries).  Log messages at
    the are generated if an ARP reply wants to overwrite a static entry, or the
    Ethernet address of a dynamic entry changed.

    ARP frames which should be send on the wire are given as a pair of buffer
    and destination address, to be passed to the underlying layer (usually
    Ethernet).  When adding entries, gratuitous ARP frames are to be sent.

    While the {!Arp_packet} module is exposed, for normal operation it is not
    needed, but this module should be sufficient.

    {e %%VERSION%% - {{:%%PKG_HOMEPAGE%% }homepage}}
*)


(** The type of an ARP handler.  It is polymorphic over the tasks waiting for
    an ARP reply. *)
type 'a t

(** {2 Constructor} *)

(** [create ~timeout ~retries mac ip)] is [t, garp].  The constructor of
    the ARP handler, specifying timeouts (defaults to 800) and amount of
    retries (defaults to 5).  For the given IPv4 address a gratuitous ARP
    request will be encoded in [garp].  The value of [timeout] is the number of
    [Tick] events.

    @raise Invalid_argument is [timeout] is 0 or negative or [retries] is
    negative.  *)
val create : ?timeout:int -> ?retries:int -> ?logsrc:Logs.src ->
  Macaddr.t -> Ipaddr.V4.t -> 'a t * (Cstruct.t * Macaddr.t)

(** [pp ppf t] prints the ARP handler [t] on [ppf] by iterating over all cache
    entries. *)
val pp : Format.formatter -> 'a t -> unit

(** {2 Predicates} *)

(** [ip t] is [ip], the configured IPv4 address. *)
val ip : 'a t -> Ipaddr.V4.t

(** [in_cache t ip] is [mac option], a MAC address if the ARP cache contains an
    entry, [None] otherwise. *)
val in_cache : 'a t -> Ipaddr.V4.t -> Macaddr.t option

(** {2 Operations on the cache} *)

(** [static t ip mac] is [t', as], where [t'] is [t] extended with a static ARP
    entry using the given [ip] and [mac].  The tasks waiting for [ip] are
    [as]. *)
val static : 'a t -> Ipaddr.V4.t -> Macaddr.t -> 'a t * 'a option

(** [alias t ip] is [t', out, as], where [t'] is [t] extended by a static ARP
    entry for [ip].  This entry will be used to answer further ARP requests.
    [out] is a gratuitous ARP frame.  The tasks waiting for [ip] are [as]. *)
val alias : 'a t -> Ipaddr.V4.t -> 'a t * (Cstruct.t * Macaddr.t) * 'a option

(** [remove t ip] is [t'], where [ip] is no longer in the cache. *)
val remove : 'a t -> Ipaddr.V4.t -> 'a t

(** {2 Events} *)

(** [tick t] is [t', requests, timeouts], which advances the state [t] into
    [t'].  Possibly retransmissions of ARP requests need to be done, provided in
    the [requests] list.  Timed out queries are in the [timeouts] list. *)
val tick : 'a t -> 'a t * (Cstruct.t * Macaddr.t) list * 'a list

(** [input t buf] is [t', reply, w], which handles the input buffer [buf] in the
    state [t].  The state is transformed into [t'].  If it was an ARP request
    for one of our IPv4 addresses, an ARP reply should be send out [reply].  If
    the input was an awaited ARP reply, some elements [w] can be informed.  *)
val input : 'a t -> Cstruct.t ->
  ('a t * (Cstruct.t * Macaddr.t) option * (Macaddr.t * 'a) option)

(** The type returned by query, either a [Mac] and a mac address, or [Wait] for
    a reply, or [RequestWait], consisting of an ARP request to be send on the wire,
    and await its answer. *)
type 'a qres =
  | Mac of Macaddr.t
  | Wait of 'a
  | RequestWait of (Cstruct.t * Macaddr.t) * 'a

(** [query t ip merge] is [t', qres], which looks for the [ip] in the cache.  If
    it is found, its value is [Mac mac].  If the [ip] is not in the cache,
    either some ['a] is waiting for it already, then the value is [Wait a],
    where [a] is produced by applying [merge (Some 'a)] to the waiting thing.
    Otherwise, both an ARP request needs to be send out, and the value of [merge
    None] is put into the cache, both as part of [RequestWait].  *)
val query : 'a t -> Ipaddr.V4.t -> ('a option -> 'a) -> 'a t * 'a qres
