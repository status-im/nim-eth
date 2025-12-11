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
    address6*: Opt[Address]
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

  let address =
    if tr.ip.isSome() and tr.udp.isSome():
      Opt.some(Address(ip: ipv4(tr.ip.get()), port: Port(tr.udp.get())))
    else:
      Opt.none(Address)

  let address6 =
    if tr.ip6.isSome():
      if tr.udp.isSome():
        Opt.some(Address(ip: ipv6(tr.ip6.get()), port: Port(tr.udp.get())))
      elif tr.udp6.isSome():
        Opt.some(Address(ip: ipv6(tr.ip6.get()), port: Port(tr.udp6.get())))
      else:
        Opt.none(Address)
    else:
      Opt.none(Address)

  Node(id: r.publicKey.toNodeId(), pubkey: r.publicKey, record: r,
    address: address, address6: address6)

func newNode*(r: Record): Result[Node, cstring] {.deprecated: "Use TypedRecord.fromRecord instead".} =
  ## Create a new `Node` from a `Record`.
  ok(Node.fromRecord(r))

func update*(n: Node, pk: PrivateKey, ip: Opt[IpAddress],
    tcpPort: Opt[Port] = Opt.none(Port),
    udpPort: Opt[Port] = Opt.none(Port),
    extraFields: openArray[FieldPair] = []): Result[void, cstring] =
  ? n.record.update(pk, ip, tcpPort, udpPort, extraFields)

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

func preferredAddress*(remote: Node, local: Node): Opt[Address] =
  ## Returns the preferred address of the remote node.
  ## If both IPv6 and IPv4 addresses are valid, IPv6 is preferred over IPv4 address.

  func isValid(localAddr: Address, remoteAddr: Address): bool =
    let
      localTA = initTAddress(localAddr.ip, localAddr.port)
      remoteTA = initTAddress(remoteAddr.ip, remoteAddr.port)

    # If remote is public, always valid
    if remoteTA.isGlobalUnicast():
      return true

    # If remote is not public, both must be loopback or private
    (localTA.isLoopback() and remoteTA.isLoopback()) or
      (localTA.isSiteLocal() and remoteTA.isSiteLocal())

  template tryAddress(localOpt, remoteOpt: Opt[Address]): Opt[Address] =
    if localOpt.isSome() and remoteOpt.isSome():
      if isValid(localOpt.get(), remoteOpt.get()):
        remoteOpt
      else:
        Opt.none(Address)
    else:
      Opt.none(Address)

  # Try IPv6 first (preferred), then IPv4
  let v6Result = tryAddress(local.address6, remote.address6)
  if v6Result.isSome():
    return v6Result

  tryAddress(local.address, remote.address)

func hasAddress*(n: Node, a: Address): bool =
  ## Returns true if the given address matches either the IPv4 or IPv6 address of the node.
  (n.address.isSome() and n.address.get() == a) or
    (n.address6.isSome() and n.address6.get() == a)

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
