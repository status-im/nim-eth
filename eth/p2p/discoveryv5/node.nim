import
  std/hashes,
  nimcrypto, stint, chronos, stew/shims/net, chronicles,
  eth/keys, enr

export stint

{.push raises: [Defect].}

type
  NodeId* = UInt256

  Address* = object
    ip*: ValidIpAddress
    port*: Port

  Node* = ref object
    id*: NodeId
    pubkey*: PublicKey
    address*: Option[Address]
    record*: Record
    seen*: bool ## Indicates if there was at least one successful
    ## request-response with this node.

func toNodeId*(pk: PublicKey): NodeId =
  ## Convert public key to a node identifier.
  readUintBE[256](keccak256.digest(pk.toRaw()).data)

func newNode*(r: Record): Result[Node, cstring] =
  ## Create a new `Node` from a `Record`.
  # TODO: Handle IPv6

  let pk = r.get(PublicKey)
  # This check is redundant for a properly created record as the deserialization
  # of a record will fail at `verifySignature` if there is no public key.
  if pk.isNone():
    return err("Could not recover public key from ENR")

  # Also this can not fail for a properly created record as id is checked upon
  # deserialization.
  let tr = ? r.toTypedRecord()
  if tr.ip.isSome() and tr.udp.isSome():
    let a = Address(ip: ipv4(tr.ip.get()), port: Port(tr.udp.get()))

    ok(Node(id: pk.get().toNodeId(), pubkey: pk.get() , record: r,
       address: some(a)))
  else:
    ok(Node(id: pk.get().toNodeId(), pubkey: pk.get(), record: r,
       address: none(Address)))

proc update*(n: Node, pk: PrivateKey, ip: Option[ValidIpAddress],
    tcpPort, udpPort: Option[Port] = none[Port](),
    extraFields: openarray[FieldPair] = []): Result[void, cstring] =
  ? n.record.update(pk, ip, tcpPort, udpPort, extraFields)

  if ip.isSome():
    if udpPort.isSome():
      let a = Address(ip: ip.get(), port: udpPort.get())
      n.address = some(a)
    elif n.address.isSome():
      let a = Address(ip: ip.get(), port: n.address.get().port)
      n.address = some(a)
    else:
      n.address = none(Address)
  else:
    n.address = none(Address)

  ok()

func hash*(n: Node): hashes.Hash = hash(n.pubkey.toRaw)

func `==`*(a, b: Node): bool =
  (a.isNil and b.isNil) or
    (not a.isNil and not b.isNil and a.pubkey == b.pubkey)

proc random*(T: type NodeId, rng: var BrHmacDrbgContext): T =
  var id: NodeId
  brHmacDrbgGenerate(addr rng, addr id, csize_t(sizeof(id)))

  id

func toBytes*(id: NodeId): array[32, byte] =
  id.toByteArrayBE()

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
chronicles.formatIt(NodeId): shortLog(it)

func hash*(a: Address): hashes.Hash =
  hashData(unsafeAddr a, sizeof(a))

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
chronicles.formatIt(Node): shortLog(it)

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
chronicles.formatIt(seq[Node]): shortLog(it)
