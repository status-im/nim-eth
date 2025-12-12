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

  Node* = ref object
    id*: NodeId
    pubkey*: PublicKey
    address*: Opt[Address]
    record*: Record
    seen*: bool ## Indicates if there was at least one successful
    ## request-response with this node.

func toNodeId*(pk: PublicKey): NodeId =
  ## Convert public key to a node identifier.
  # Keccak256 hash is used as defined in ENR spec for scheme v4:
  # https://github.com/ethereum/devp2p/blob/master/enr.md#v4-identity-scheme
  # The raw key used is the uncompressed public key.
  readUintBE[256](Keccak256.digest(pk.toRaw()).data)

func fromRecord*(T: type Node, r: Record): T =
  ## Create a new `Node` from a `Record`.
  let tr = TypedRecord.fromRecord(r)
  if tr.ip.isSome() and tr.udp.isSome():
    let a = Address(ip: ipv4(tr.ip.get()), port: Port(tr.udp.get()))

    Node(id: r.publicKey.toNodeId(), pubkey: r.publicKey, record: r,
       address: Opt.some(a))
  else:
    Node(id: r.publicKey.toNodeId(), pubkey: r.publicKey, record: r,
       address: Opt.none(Address))

func newNode*(r: Record): Result[Node, cstring] {.deprecated: "Use TypedRecord.fromRecord instead".} =
  ## Create a new `Node` from a `Record`.
  ok(Node.fromRecord(r))

func update*(n: Node, pk: PrivateKey, ip: Opt[IpAddress],
    tcpPort: Opt[Port] = Opt.none(Port),
    udpPort: Opt[Port] = Opt.none(Port),
    quicPort: Opt[Port] = Opt.none(Port),
    extraFields: openArray[FieldPair] = []): Result[void, cstring] =
  ? n.record.update(pk, ip, tcpPort, udpPort, quicPort, extraFields)

  if ip.isSome():
    if udpPort.isSome():
      let a = Address(ip: ip.get(), port: udpPort.get())
      n.address = Opt.some(a)
    elif n.address.isSome():
      let a = Address(ip: ip.get(), port: n.address.get().port)
      n.address = Opt.some(a)
    else:
      n.address = Opt.none(Address)
  else:
    n.address = Opt.none(Address)

  ok()

func hash*(n: Node): hashes.Hash = hash(n.pubkey.toRaw)

func `==`*(a, b: Node): bool =
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

func shortLog*(n: Node): string =
  if n.isNil:
    "uninitialized"
  elif n.address.isNone():
    shortLog(n.id) & ":unaddressable"
  else:
    shortLog(n.id) & ":" & $n.address.get()

func shortLog*(nodes: seq[Node]): string =
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
chronicles.formatIt(Node): shortLog(it)
chronicles.formatIt(seq[Node]): shortLog(it)
