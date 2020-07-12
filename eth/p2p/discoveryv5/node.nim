import
  std/hashes,
  nimcrypto, stint, chronos, stew/shims/net,
  eth/keys, enr

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

proc toNodeId*(pk: PublicKey): NodeId =
  ## Convert public key to a node identifier.
  readUintBE[256](keccak256.digest(pk.toRaw()).data)

proc newNode*(r: Record): Result[Node, cstring] =
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

proc hash*(n: Node): hashes.Hash = hash(n.pubkey.toRaw)
proc `==`*(a, b: Node): bool =
  (a.isNil and b.isNil) or
    (not a.isNil and not b.isNil and a.pubkey == b.pubkey)

proc `$`*(a: Address): string =
  result.add($a.ip)
  result.add(":" & $a.port)

proc `$`*(n: Node): string =
  if n == nil:
    "Node[uninitialized]"
  elif n.address.isNone():
    "Node[unaddressable]"
  else:
    "Node[" & $n.address.get().ip & ":" & $n.address.get().port & "]"
