# nim-eth - Node Discovery Protocol v5
# Copyright (c) 2020-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[hashes, net],
  stint, chronos, chronicles, results,
  ../../keccak/keccak,
  ../../net/utils,
  ../../enr/enr

export stint, results, enr

type
  NodeId* = UInt256

  Address* = object
    ip*: IpAddress
    port*: Port

  DiscoveryNode* = ref object
    ## A peer in the DHT. Treated as immutable after construction: a peer with
    ## an updated record is a new `DiscoveryNode` that replaces the old one.
    ## Only `seen` is meant to be set.
    id: NodeId
    pubkey: PublicKey
    address: Opt[Address]
    record: Record
    seen*: bool ## Indicates if there was at least one successful
    ## request-response with this node.

  LocalDiscoveryNode* = ref object
    ## Local discovery identity and the record advertised. The record and thus
    ## the addresses can change over time.
    id*: NodeId
    pubkey*: PublicKey
    address*: Opt[Address]
    record*: Record

func id*(n: DiscoveryNode): lent NodeId =
  n.id

func pubkey*(n: DiscoveryNode): lent PublicKey =
  n.pubkey

func address*(n: DiscoveryNode): lent Opt[Address] =
  n.address

func record*(n: DiscoveryNode): lent Record =
  n.record

func toNodeId*(pk: PublicKey): NodeId =
  ## Convert public key to a node identifier.
  # Keccak256 hash is used as defined in ENR spec for scheme v4:
  # https://github.com/ethereum/devp2p/blob/master/enr.md#v4-identity-scheme
  # The raw key used is the uncompressed public key.
  readUintBE[256](Keccak256.digest(pk.toRaw()).data)

func address(r: Record): Opt[Address] =
  ## Derive the endpoint that is advertised in the record.
  let tr = TypedRecord.fromRecord(r)
  if tr.ip.isSome() and tr.udp.isSome() and tr.udp.get() != 0:
    # Port 0 is reserved (RFC 6335) and not routable as a destination.
    # Reject it here so peers with udp = 0 cannot enter the routing table
    # nor be returned in NODES responses.
    Opt.some(Address(ip: ipv4(tr.ip.get()), port: Port(tr.udp.get())))
  else:
    Opt.none(Address)

func fromRecord*(T: type DiscoveryNode, r: Record): T =
  ## Create a new `DiscoveryNode` from a `Record`.
  DiscoveryNode(id: r.publicKey.toNodeId(), pubkey: r.publicKey, record: r,
    address: r.address())

func fromRecord*(T: type LocalDiscoveryNode, r: Record): T =
  ## Create a new `LocalDiscoveryNode` from a `Record`.
  LocalDiscoveryNode(id: r.publicKey.toNodeId(), pubkey: r.publicKey, record: r,
    address: r.address())

func toNode*(ln: LocalDiscoveryNode): DiscoveryNode =
  ## A snapshot of the `LocalDiscoveryNode` for the places where it appears as
  ## a peer, such as the NODES response to a request at distance 0.
  DiscoveryNode(id: ln.id, pubkey: ln.pubkey, record: ln.record,
    address: ln.address)

func update*(ln: LocalDiscoveryNode, pk: PrivateKey,
    ip: Opt[IpAddress] = Opt.none(IpAddress),
    tcpPort: Opt[Port] = Opt.none(Port),
    udpPort: Opt[Port] = Opt.none(Port),
    quicPort: Opt[Port] = Opt.none(Port),
    extraFields: openArray[FieldPair] = []): Result[void, cstring] =
  ## Update the record and the address of the `LocalDiscoveryNode`.
  ? ln.record.update(pk, ip, tcpPort, udpPort, quicPort, extraFields)

  ln.address = ln.record.address()

  ok()

func hash*(n: DiscoveryNode): hashes.Hash = hash(n.pubkey.toRaw)

func `==`*(a, b: DiscoveryNode): bool =
  (a.isNil and b.isNil) or
    (not a.isNil and not b.isNil and a.pubkey == b.pubkey)

func hash*(id: NodeId): Hash =
  hash(id.toBytesBE)

proc random*(T: type NodeId, rng: var HmacDrbgContext): T =
  rng.generate(T)

func `$`*(id: NodeId): string =
  id.toHex()

func shortLog*(id: NodeId): string =
  ## Returns compact string representation of ``id``.
  var sid = $id
  if len(sid) <= 10:
    result = sid
  else:
    result = newStringOfCap(10)
    for i in 0..<2:
      result.add(sid[i])
    result.add("*")
    for i in (len(sid) - 6)..sid.high:
      result.add(sid[i])

func hash*(a: Address): hashes.Hash =
  let res = a.ip.hash !& a.port.hash
  !$res

func `$`*(a: Address): string =
  result.add($a.ip)
  result.add(":" & $a.port)

func shortLog*(n: DiscoveryNode): string =
  if n.isNil:
    "uninitialized"
  elif n.address.isNone():
    shortLog(n.id) & ":unaddressable"
  else:
    shortLog(n.id) & ":" & $n.address.get()

func shortLog*(ln: LocalDiscoveryNode): string =
  if ln.isNil:
    "uninitialized"
  elif ln.address.isNone():
    shortLog(ln.id) & ":unaddressable"
  else:
    shortLog(ln.id) & ":" & $ln.address.get()

func shortLog*(nodes: seq[DiscoveryNode]): string =
  result = "["

  var first = true
  for n in nodes:
    if first:
      first = false
    else:
      result.add(", ")
    result.add(shortLog(n))

  result.add("]")

chronicles.formatIt(NodeId): shortLog(it)
chronicles.formatIt(Address): $it
chronicles.formatIt(DiscoveryNode): shortLog(it)
chronicles.formatIt(seq[DiscoveryNode]): shortLog(it)
chronicles.formatIt(LocalDiscoveryNode): shortLog(it)

# Deprecated API, kept for backwards compatibility only.

type Node* {.deprecated: "Use DiscoveryNode".} = DiscoveryNode
  ## The peer type was called `Node`, which is ambiguous in a codebase that
  ## has a node type per protocol and per client.

func newNode*(r: Record): Result[DiscoveryNode, cstring]
    {.deprecated: "Use DiscoveryNode.fromRecord instead".} =
  ## Create a new `DiscoveryNode` from a `Record`.
  ok(DiscoveryNode.fromRecord(r))

converter toNodeCompat*(ln: LocalDiscoveryNode): DiscoveryNode
    {.deprecated: "A LocalDiscoveryNode is not a peer, use " &
      "LocalDiscoveryNode.toNode() for an explicit snapshot".} =
  ## Keeps passing a `LocalDiscoveryNode` where a `DiscoveryNode` is expected
  ## still possible.
  ln.toNode()
