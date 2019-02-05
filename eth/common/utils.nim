import nimcrypto, hashes, byteutils, eth_types

proc hash*(d: MDigest): Hash {.inline.} = hash(d.data)

proc parseAddress*(hexString: string): EthAddress =
  hexToPaddedByteArray[20](hexString)

proc `$`*(a: EthAddress): string =
  a.toHex()

