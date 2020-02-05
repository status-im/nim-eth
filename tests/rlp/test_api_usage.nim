import
  math, unittest, strutils,
  eth/rlp, util/json_testing

proc q(s: string): string = "\"" & s & "\""
proc i(s: string): string = s.replace(" ").replace("\n")
proc inspectMatch(r: Rlp, s: string): bool = r.inspect.i == s.i

test "empty bytes are not a proper RLP":
  var rlp = rlpFromBytes Bytes(@[]).toRange

  check:
    not rlp.hasData
    not rlp.isBlob
    not rlp.isList
    not rlp.isEmpty

  expect Exception:
    rlp.skipElem

  expect Exception:
    discard rlp.getType

  expect Exception:
    for e in rlp:
      discard e.getType

test "you cannot finish a list without appending enough elements":
  var writer = initRlpList(3)
  writer.append "foo"
  writer.append "bar"

  expect Defect:
    let result = writer.finish

proc withNewLines(x: string): string = x & "\n"

test "encode/decode object":
  type
    MyEnum = enum
      foo,
      bar

    MyObj = object
      a: array[3, char]
      b: int
      c: MyEnum

  var input: MyObj
  input.a = ['e', 't', 'h']
  input.b = 63
  input.c = bar

  var writer = initRlpWriter()
  writer.append(input)
  let bytes = writer.finish()
  var rlp = rlpFromBytes(bytes.toRange)

  var output = rlp.read(MyObj)
  check:
    input == output

test "encode and decode lists":
  var writer = initRlpList(3)
  writer.append "foo"
  writer.append ["bar", "baz"]
  writer.append [30, 40, 50]

  var
    bytes = writer.finish
    rlp = rlpFromBytes bytes.toRange

  check:
    bytes.hexRepr == "d183666f6fc8836261728362617ac31e2832"
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

  bytes = encodeList(6000,
                     "Lorem ipsum dolor sit amet",
                     "Donec ligula tortor, egestas eu est vitae")

  rlp = rlpFromBytes bytes.toRange
  check:
    rlp.listLen == 3
    rlp.listElem(0).toInt(int) == 6000
    rlp.listElem(1).toString == "Lorem ipsum dolor sit amet"
    rlp.listElem(2).toString == "Donec ligula tortor, egestas eu est vitae"

  # test creating RLPs from other RLPs
  var list = rlpFromBytes encodeList(rlp.listELem(1), rlp.listELem(0)).toRange

  # test that iteration with enterList/skipElem works as expected
  list.enterList
  check list.toString == "Lorem ipsum dolor sit amet"
  list.skipElem

  check list.toInt(int32) == 6000.int32
  var intVar: int
  list >> intVar
  check intVar == 6000

  check(not list.hasData)
  expect Exception: list.skipElem

test "toBytes":
  let rlp = rlpFromHex("f2cb847f000001827666827666a040ef02798f211da2e8173d37f255be908871ae65060dbb2f77fb29c0421447f4845ab90b50")
  let tok = rlp.listElem(1).toBytes()
  check:
    tok.len == 32
    tok.hexRepr == "40ef02798f211da2e8173d37f255be908871ae65060dbb2f77fb29c0421447f4"

test "nested lists":
  let listBytes = encode([[1, 2, 3], [5, 6, 7]])
  let listRlp = rlpFromBytes listBytes.toRange
  let sublistRlp0 = listRlp.listElem(0)
  let sublistRlp1 = listRlp.listElem(1)
  check sublistRlp0.listElem(0).toInt(int) == 1
  check sublistRlp0.listElem(1).toInt(int) == 2
  check sublistRlp0.listElem(2).toInt(int) == 3
  check sublistRlp1.listElem(0).toInt(int) == 5
  check sublistRlp1.listElem(1).toInt(int) == 6
  check sublistRlp1.listElem(2).toInt(int) == 7

test "encoding length":
  let listBytes = encode([1,2,3,4,5])
  let listRlp = rlpFromBytes listBytes.toRange
  check listRlp.listLen == 5

  let emptyListBytes = encode ""
  check emptyListBytes.len == 1
  let emptyListRlp = rlpFromBytes emptyListBytes.toRange
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

  let rlp = rlpFromBytes(encode((b1, b2, b3)).toRange)
  check:
    rlp.listLen == 3
    rlp.listElem(0).toBytes().toSeq() == @b1
    rlp.listElem(1).toBytes().toSeq() == @b2
    rlp.listElem(2).toBytes().toSeq() == @b3

    # The first byte here is the length of the datum (132 - 128 => 4)
    $(rlp.listElem(1).rawData) == "R[132, 6, 8, 12, 123]"

test "empty byte arrays":
  var
    rlp = rlpFromBytes rlp.encode("").toRange
    b = rlp.toBytes
  check $b == "R[]"

test "encode/decode floats":
  for f in [high(float64), low(float64), 0.1, 122.23,
            103487315.128934,
            1943935743563457201.391754032785692,
            0, -0,
            Inf, NegInf, NaN]:

    template isNaN(n): bool =
      classify(n) == fcNaN

    template chk(input) =
      let restored = decode(encode(input), float64)
      check restored == input or (input.isNaN and restored.isNaN)

    chk  f
    chk -f

