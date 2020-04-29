import
  std/[net, hashes], nimcrypto, stint, chronicles,
  types, enr, eth/keys, ../enode

{.push raises: [Defect].}

type
  Node* = ref object
    node*: ENode
    id*: NodeId
    record*: Record

proc toNodeId*(pk: PublicKey): NodeId =
  readUintBE[256](keccak256.digest(pk.toRaw()).data)

# TODO: Lets not allow to create a node where enode info is not in sync with the
# record
proc newNode*(enode: ENode, r: Record): Node =
  Node(node: enode,
       id: enode.pubkey.toNodeId(),
       record: r)

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
  except KeyError, ValueError:
    # TODO: This will result in a 0.0.0.0 address. Might introduce more bugs.
    # Maybe we shouldn't allow the creation of Node from Record without IP.
    # Will need some refactor though.
    discard

  let pk = r.get(PublicKey)
  if pk.isNone():
    warn "Could not recover public key from ENR"
    return

  let enode = ENode(pubkey: pk.get(), address: a)
  result = Node(node: enode,
                id: enode.pubkey.toNodeId(),
                record: r)

proc hash*(n: Node): hashes.Hash = hash(n.node.pubkey.toRaw)
proc `==`*(a, b: Node): bool {.raises: [].} =
  (a.isNil and b.isNil) or
    (not a.isNil and not b.isNil and a.node.pubkey == b.node.pubkey)

proc address*(n: Node): Address {.inline, raises: [].} = n.node.address

proc updateEndpoint*(n: Node, a: Address) {.inline, raises: [].} =
  n.node.address = a

proc `$`*(n: Node): string {.raises: [].} =
  if n == nil:
    "Node[local]"
  else:
    "Node[" & $n.node.address.ip & ":" & $n.node.address.udpPort & "]"
