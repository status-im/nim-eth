import
  std/[net, hashes], nimcrypto, stint, chronicles,
  types, enr, eth/keys, ../enode

type
  Node* = ref object
    node*: ENode
    id*: NodeId
    record*: Record

proc toNodeId*(pk: PublicKey): NodeId =
  readUintBE[256](keccak256.digest(pk.getRaw()).data)

proc newNode*(enode: ENode): Node =
  Node(node: enode,
       id: enode.pubkey.toNodeId())

proc newNode*(enode: ENode, r: Record): Node =
  Node(node: enode,
       id: enode.pubkey.toNodeId(),
       record: r)

proc newNode*(uriString: string): Node =
  newNode initENode(uriString)

proc newNode*(pk: PublicKey, address: Address): Node =
  newNode initENode(pk, address)

proc newNode*(r: Record): Node =
  # TODO: Handle IPv6
  var a: Address
  try:
    let
      ipBytes = r.get("ip", array[4, byte])
      udpPort = r.get("udp", uint16)

    a = Address(ip: IpAddress(family: IpAddressFamily.IPv4,
                              address_v4: ipBytes),
                udpPort: Port udpPort)
  except KeyError:
    # TODO: This will result in a 0.0.0.0 address. Might introduce more bugs.
    # Maybe we shouldn't allow the creation of Node from Record without IP.
    # Will need some refactor though.
    discard

  var pk: PublicKey
  if recoverPublicKey(r.get("secp256k1", seq[byte]), pk) != EthKeysStatus.Success:
    warn "Could not recover public key"
    return

  result = newNode(initENode(pk, a))
  result.record = r

proc hash*(n: Node): hashes.Hash = hash(n.node.pubkey.data)
proc `==`*(a, b: Node): bool = (a.isNil and b.isNil) or (not a.isNil and not b.isNil and a.node.pubkey == b.node.pubkey)

proc address*(n: Node): Address {.inline.} = n.node.address

proc updateEndpoint*(n: Node, a: Address) {.inline.} = n.node.address = a

proc `$`*(n: Node): string =
  if n == nil:
    "Node[local]"
  else:
    "Node[" & $n.node.address.ip & ":" & $n.node.address.udpPort & "]"
