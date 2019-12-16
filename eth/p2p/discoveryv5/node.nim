import std/[net, endians, hashes]
import nimcrypto, stint
import types, enr, eth/keys, ../enode

type
  Node* = ref object
    node*: ENode
    id*: NodeId
    record*: Record

proc toNodeId*(pk: PublicKey): NodeId =
  readUintBE[256](keccak256.digest(pk.getRaw()).data)

proc newNode*(pk: PublicKey, address: Address): Node =
  result.new()
  result.node = initENode(pk, address)
  result.id = pk.toNodeId()

proc newNode*(uriString: string): Node =
  result.new()
  result.node = initENode(uriString)
  result.id = result.node.pubkey.toNodeId()

proc newNode*(enode: ENode): Node =
  result.new()
  result.node = enode
  result.id = result.node.pubkey.toNodeId()

proc newNode*(r: Record): Node =
  var a: Address
  var pk: PublicKey
  # TODO: Handle IPv6
  var ip = r.get("ip", int32)

  a.ip = IpAddress(family: IpAddressFamily.IPv4)
  bigEndian32(addr a.ip.address_v4, addr ip)

  a.udpPort = Port(r.get("udp", int))
  if recoverPublicKey(r.get("secp256k1", seq[byte]), pk) != EthKeysStatus.Success:
    echo "Could not recover public key"

  result = newNode(initENode(pk, a))
  result.record = r

proc hash*(n: Node): hashes.Hash = hash(n.node.pubkey.data)
proc `==`*(a, b: Node): bool = (a.isNil and b.isNil) or (not a.isNil and not b.isNil and a.node.pubkey == b.node.pubkey)

proc `$`*(n: Node): string =
  if n == nil:
    "Node[local]"
  else:
    "Node[" & $n.node.address.ip & ":" & $n.node.address.udpPort & "]"
