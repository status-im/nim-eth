import nimcrypto, hashes, stew/byteutils, eth_types, metrics

export metrics

proc hash*(d: MDigest): Hash {.inline.} = hash(d.data)

proc parseAddress*(hexString: string): EthAddress =
  hexToPaddedByteArray[20](hexString)

proc `$`*(a: EthAddress): string =
  a.toHex()

var peerGauge* = newGauge("connected peers", "number of peers in the pool")

