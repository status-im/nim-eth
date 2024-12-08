{.used.}

import
  std/[math, strutils],
  unittest2,
  stew/byteutils,
  ../../eth/[common, rlp]

proc q(s: string): string = "\"" & s & "\""
proc i(s: string): string = s.replace(" ").replace("\n")
proc inspectMatch(r: Rlp, s: string): bool = r.inspect.i == s.i

proc `==`(a,b: ChainId): bool {.borrow.}
  ## helper for ` test_calcBlockBodyTranscode()`

proc test_blockBodyTranscode() =
  ## RLP encode/decode a list of `BlockBody` objects. Note that tere is/was a
  ## problem in `eth/common/eth_types_rlp.append()` for `BlockBody` encoding.
  let blkSeq = @[
    BlockBody(
      transactions: @[
        Transaction(nonce: 1)]),
    BlockBody(
      uncles: @[Header(nonce: Bytes8([0x20u8,0,0,0,0,0,0,0]))]),
    BlockBody(),
    BlockBody(
      transactions: @[
        Transaction(nonce: 3),
        Transaction(nonce: 4)])]

  let temp = blkSeq.encode

  debugEcho temp
  
  let trBlkSeq = temp.decode(typeof blkSeq)

  check trBlkSeq.len == blkSeq.len
  for n in 0 ..< min(trBlkSeq.len, trBlkSeq.len):
    check (n, trBlkSeq[n]) == (n, blkSeq[n])

suite "test api usage":
  test "encode and decode block body":
    test_blockBodyTranscode()
