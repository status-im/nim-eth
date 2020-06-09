import
  std/hashes, nimcrypto, stint, chronos, stew/shims/net,
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

proc toNodeId*(pk: PublicKey): NodeId =
  readUintBE[256](keccak256.digest(pk.toRaw()).data)

proc newNode*(r: Record): Result[Node, cstring] =
  # TODO: Handle IPv6

  let pk = r.get(PublicKey)
  # This check is redundant as the deserialisation of `Record` will already fail
  # at `verifySignature` if there is no public key
  if pk.isNone():
    return err("Could not recover public key from ENR")

  let tr = ? r.toTypedRecord()
  if tr.ip.isSome() and tr.udp.isSome():
    let
      ip = ValidIpAddress.init(
        IpAddress(family: IpAddressFamily.IPv4, address_v4: tr.ip.get()))
      a = Address(ip: ip, port: Port(tr.udp.get()))

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
