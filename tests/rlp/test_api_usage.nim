# eth
# Copyright (c) 2019-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/strutils,
  unittest2,
  stew/byteutils,
  ../../eth/[common, rlp]

proc q(s: string): string = "\"" & s & "\""
proc i(s: string): string = s.replace(" ").replace("\n")
proc inspectMatch(r: Rlp, s: string): bool = r.inspect.i == s.i

proc test_blockBodyTranscode() =
  ## RLP encode/decode a list of `BlockBody` objects. Note that there is/was a
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

  let trBlkSeq = blkSeq.encode.decode(typeof blkSeq)

  check trBlkSeq.len == blkSeq.len
  for n in 0 ..< min(trBlkSeq.len, trBlkSeq.len):
    check (n, trBlkSeq[n]) == (n, blkSeq[n])

suite "test api usage":
  test "empty bytes are not a proper RLP":
    var rlp = rlpFromBytes seq[byte](@[])

    check:
      not rlp.hasData
      not rlp.isBlob
      not rlp.isList
      not rlp.isEmpty

    expect AssertionDefect:
      rlp.skipElem

  test "you cannot finish a list without appending enough elements":
    var writer = initRlpList(3)
    writer.append "foo"
    writer.append "bar"

    expect AssertionDefect:
      discard writer.finish

  test "encode/decode object":
    type
      MyEnum = enum
        foo,
        bar

      MyObj = object
        a: array[3, char]
        b: uint64
        c: MyEnum

      IntObj = object
        v: int

    var input: MyObj
    input.a = ['e', 't', 'h']
    input.b = 63
    input.c = bar


    var writer = initRlpWriter()
    writer.append(input)

    check:
      not compiles(writer.append(default(IntObj)))

    let bytes = writer.finish()
    var rlp = rlpFromBytes(bytes)

    var output = rlp.read(MyObj)
    check:
      input == output

  test "encode and decode lists":
    var writer = initRlpList(3)
    writer.append "foo"
    writer.append ["bar", "baz"]
    writer.append [uint64 30, 40, 50]

    var
      bytes = writer.finish
      rlp = rlpFromBytes bytes

    check:
      bytes.toHex == "d183666f6fc8836261728362617ac31e2832"
      rlp.inspectMatch """
        {
          "foo"
          {
            "bar"
            "baz"
          }
          {
            byte 30
            byte 40
            byte 50
          }
        }
      """

    bytes = encodeList(uint64 6000,
                      "Lorem ipsum dolor sit amet",
                      "Donec ligula tortor, egestas eu est vitae")

    rlp = rlpFromBytes bytes
    check:
      rlp.listLen == 3
      rlp.listElem(0).toInt(uint64) == 6000
      rlp.listElem(1).toString == "Lorem ipsum dolor sit amet"
      rlp.listElem(2).toString == "Donec ligula tortor, egestas eu est vitae"

    # test creating RLPs from other RLPs
    var list = rlpFromBytes encodeList(rlp.listElem(1), rlp.listElem(0))

    # test that iteration with enterList/skipElem works as expected
    doAssert list.enterList # We already know that we are working with a list
    check list.toString == "Lorem ipsum dolor sit amet"
    list.skipElem

    check list.toInt(uint32) == 6000.uint32
    var intVar: uint32
    list >> intVar
    check intVar == 6000

    check(not list.hasData)
    expect AssertionDefect: list.skipElem

  test "encode and decode block body":
    test_blockBodyTranscode()

  test "toBytes":
    let rlp = rlpFromHex("f2cb847f000001827666827666a040ef02798f211da2e8173d37f255be908871ae65060dbb2f77fb29c0421447f4845ab90b50")
    let tok = rlp.listElem(1).toBytes()
    check:
      tok.len == 32
      tok.toHex == "40ef02798f211da2e8173d37f255be908871ae65060dbb2f77fb29c0421447f4"

  test "nested lists":
    let listBytes = encode([[uint64 1, 2, 3], [uint64 5, 6, 7]])
    let listRlp = rlpFromBytes listBytes
    let sublistRlp0 = listRlp.listElem(0)
    let sublistRlp1 = listRlp.listElem(1)
    check sublistRlp0.listElem(0).toInt(uint64) == 1
    check sublistRlp0.listElem(1).toInt(uint64) == 2
    check sublistRlp0.listElem(2).toInt(uint64) == 3
    check sublistRlp1.listElem(0).toInt(uint64) == 5
    check sublistRlp1.listElem(1).toInt(uint64) == 6
    check sublistRlp1.listElem(2).toInt(uint64) == 7

  test "encoding length":
    let listBytes = encode([uint64 1,2,3,4,5])
    let listRlp = rlpFromBytes listBytes
    check listRlp.listLen == 5

    let emptyListBytes = encode ""
    check emptyListBytes.len == 1
    let emptyListRlp = rlpFromBytes emptyListBytes
    check emptyListRlp.blobLen == 0

  test "basic decoding":
    var rlp1 = rlpFromHex("856d6f6f7365")
    var rlp2 = rlpFromHex("0x856d6f6f7365")

    check:
      rlp1.inspect == q"moose"
      rlp2.inspect == q"moose"

  test "malformed/truncated RLP":
    var rlp = rlpFromHex("b8056d6f6f7365")
    expect MalformedRlpError:
      discard rlp.inspect

  test "encode byte arrays":
    var b1 = [byte(1), 2, 5, 7, 8]
    var b2 = [byte(6), 8, 12, 123]
    var b3 = @[byte(122), 56, 65, 12]

    let rlp = rlpFromBytes(encode((b1, b2, b3)))
    check:
      rlp.listLen == 3
      rlp.listElem(0).toBytes() == b1
      rlp.listElem(1).toBytes() == b2
      rlp.listElem(2).toBytes() == b3

      # The first byte here is the length of the datum (132 - 128 => 4)
      $(rlp.listElem(1).rawData) == "[132, 6, 8, 12, 123]"

  test "empty byte arrays":
    var
      rlp = rlpFromBytes rlp.encode("")
      b = rlp.toBytes
    check $b == "@[]"

  test "invalid enum":
    type
      MyEnum = enum
        foo = 0x00,
        bar = 0x01

    var writer = initRlpWriter()
    writer.append(byte 1) # valid
    writer.append(byte 2) # invalid
    writer.append(cast[uint64](-1)) # invalid
    let bytes = writer.finish()
    var rlp = rlpFromBytes(bytes)

    check rlp.read(MyEnum) == bar

    expect RlpTypeMismatch:
      discard rlp.read(MyEnum)
    rlp.skipElem()

    expect RlpTypeMismatch:
      discard rlp.read(MyEnum)

  test "invalid enum - enum with hole":
    type
      MyEnum = enum
        foo = 0x00,
        bar = 0x01,
        baz = 0x0100

    var writer = initRlpWriter()
    writer.append(1'u64) # valid
    writer.append(2'u64) # invalid - enum hole value
    writer.append(256'u64) # valid
    writer.append(257'u64) # invalid - too large
    let bytes = writer.finish()
    var rlp = rlpFromBytes(bytes)

    check rlp.read(MyEnum) == bar

    expect RlpTypeMismatch:
      discard rlp.read(MyEnum)
    rlp.skipElem()

    check rlp.read(MyEnum) == baz

    expect RlpTypeMismatch:
      discard rlp.read(MyEnum)
    rlp.skipElem()

  test "encodeInt basics":
    for i in [uint64 0, 1, 10, 100, 1000, uint64.high]:
      check:
        encode(i) == encodeInt(i).data()
