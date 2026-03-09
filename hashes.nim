{.push raises: [].}
import
  std/[hashes, macros, typetraits],
  stint,
  results,
  stew/[assign2, byteutils, endians2, staticfor],
  nimcrypto/keccak,
  ./writer
export stint, hashes, results, keccak.update, keccak.finish, writer

# FixedBytes (was base.nim)
type
  FixedBytes*[N: static int] = distinct array[N, byte]
template to*[N: static int](v: array[N, byte], T: type FixedBytes[N]): untyped =
  FixedBytes[sizeof(v)](v)
template data*[N: static int](v: FixedBytes[N]): array[N, byte] =
  distinctBase(v)
func copyFrom*[N: static int](T: type FixedBytes[N], v: openArray[byte], start = 0): T =
  if v.len > start:
    let n = min(N, v.len - start)
    assign(result.data.toOpenArray(0, n - 1), v.toOpenArray(start, start + n - 1))
template default*[N](T: type FixedBytes[N]): T =
  const def = system.default(T)
  def
func `==`*(a, b: FixedBytes): bool {.inline.} =
  equalMem(addr a.data[0], addr b.data[0], a.N)
func fromHex*(T: type FixedBytes, c: openArray[char]): T {.raises: [ValueError].} =
  T(hexToByteArrayStrict(c, T.N))
template makeFixedBytesN(N: static int) =
  type `Bytes N`* = FixedBytes[N]
  const `zeroBytes N`* = system.default(`Bytes N`)
  template default*(T: type `Bytes N`): `Bytes N` =
    `zeroBytes N`
  template `bytes N`*(s: static string): `Bytes N` =
    `Bytes N`.fromHex(s)
makeFixedBytesN(32)

# Hash32 (was hashes.nim)
type
  Hash32* = distinct Bytes32
template data*(v: Hash32): array[32, byte] =
  distinctBase(v)
template copyFrom*(T: type Hash32, v: openArray[byte], start = 0): T =
  Hash32(Bytes32.copyFrom(v, start))
func `==`*(a, b: Hash32): bool {.borrow.}
func fromHex*(_: type Hash32, s: openArray[char]): Hash32 {.raises: [ValueError].} =
  Hash32(Bytes32.fromHex(s))
template to*(s: static string, _: type Hash32): Hash32 =
  const hash = Hash32.fromHex(s)
  hash
template hash32*(s: static string): Hash32 =
  s.to(Hash32)
template to*(v: MDigest[256], _: type Hash32): Hash32 =
  Hash32(v.data)
func keccak256*(input: openArray[byte]): Hash32 =
  var ctx: keccak.keccak256
  ctx.update(input)
  ctx.finish().to(Hash32)

# hashes_rlp
proc read*(rlp: var Rlp, T: type Hash32): Hash32 {.raises: [RlpError].} =
  Hash32(rlp.read(type(result.data)))
proc append*(rlpWriter: var RlpWriter, a: Hash32) =
  rlpWriter.append(a.data)
