{.used.}

import
  std/times,
  unittest2,
  stew/byteutils,
  results,
  ../../eth/rlp,
  ../../eth/common/hashes

type
  Transaction = object
    sender: string
    receiver: string
    amount: uint64
    time {.rlpIgnore.}: uint64

  Point = object
    x: uint64
    y: uint64

  Segment = object
    a: Point
    b: Point

  Foo = object
    x: uint64
    y: string
    z: seq[uint64]

  Bar = object
    b: string
    f: Foo

  CustomSerialized = object
    customFoo {.rlpCustomSerialization.}: Foo
    ignored {.rlpIgnore.}: uint64

  TrailingWithIgnored = object
    a: uint64
    b: Opt[uint64]
    c: Opt[uint64]
    cache {.rlpIgnore.}: int

proc append*(rlpWriter: var RlpWriter, holder: CustomSerialized, f: Foo) =
  rlpWriter.startList(3)
  rlpWriter.append(f.x)
  rlpWriter.append(uint64 f.y.len)
  rlpWriter.append(holder.ignored)

proc read*(rlp: var Rlp, holder: var CustomSerialized, T: type Foo): Foo =
  rlp.consumeList:
    let
      x = rlp.read(uint64)
      yLen = rlp.read(uint64)
    holder.ignored = rlp.read(uint64) * 2
  Foo(x: x, y: newString(yLen))

proc suite() =
  suite "object serialization":
    test "trailing optional fields (with ignored field)":
      let obj = TrailingWithIgnored(
        a: 1, b: Opt.some(2'u64), c: Opt.some(3'u64), cache: 4)
      check:
        rlp.decode(rlp.encode(obj), TrailingWithIgnored) ==
          TrailingWithIgnored(a: 1, b: Opt.some(2'u64), c: Opt.some(3'u64))
      expect AssertionDefect:
        discard rlp.encode(TrailingWithIgnored(a: 1, c: Opt.some(3'u64)))

    test "encoding and decoding an object":
      var originalBar = Bar(b: "abracadabra",
                            f: Foo(x: 5'u64, y: "hocus pocus", z: @[uint64 100, 200, 300]))

      var bytes = encode(originalBar)
      var r = rlpFromBytes(bytes)
      var restoredBar = r.read(Bar)

      check:
        originalBar == restoredBar

      var t1 = Transaction(sender: "Alice", receiver: "Bob", amount: 1000, time: 100)
      bytes = encode(t1)
      var t2 = bytes.decode(Transaction)

      check:
        bytes.toHex == "cd85416c69636583426f628203e8" # verifies that Alice comes first
        t2.time == 0
        t2.sender == "Alice"
        t2.receiver == "Bob"
        t2.amount == 1000

    test "custom field serialization":
      var origVal = CustomSerialized(customFoo: Foo(x: 10'u64, y: "y", z: @[]), ignored: 5)
      var bytes = encode(origVal)
      var r = rlpFromBytes(bytes)
      var restored = r.read(CustomSerialized)

      check:
        origVal.customFoo.x == restored.customFoo.x
        origVal.customFoo.y.len == restored.customFoo.y.len
        restored.ignored == 10

    test "object with additional list elements":
      expect MalformedRlpError:
        discard encode((1'u64, 2'u64, 3'u64)).decode(Point)
      expect MalformedRlpError:
        discard encode(((1'u64, 2'u64, 99'u64), (3'u64, 4'u64))).decode(Segment)

    test "tuple with additional list elements":
      expect MalformedRlpError:
        discard encode((1'u64, 2'u64, 3'u64)).decode((uint64, uint64))

    test "RLP fields count":
      check:
        Bar.rlpFieldsCount == 2
        Foo.rlpFieldsCount == 3
        Transaction.rlpFieldsCount == 3

    test "RLP size w/o data encoding":
      var
        originalBar = Bar(b: "abracadabra",
                            f: Foo(x: 5'u64, y: "hocus pocus", z: @[uint64 100, 200, 300]))
        originalBarBytes = encode(originalBar)

        origVal = CustomSerialized(customFoo: Foo(x: 10'u64, y: "y", z: @[]), ignored: 5)
        origValBytes = encode(origVal)

      check:
        originalBarBytes.len == originalBar.getEncodedLength
        origValBytes.len == origVal.getEncodedLength

    test "getEncodedLengthAndHash":
      var
        originalBar = Bar(b: "abracadabra",
                            f: Foo(x: 5'u64, y: "hocus pocus", z: @[uint64 100, 200, 300]))
        originalBarBytes = encode(originalBar)
        originalBarHash  = computeRlpHash(originalBar)
        (length, hash)   = getEncodedLengthAndHash(originalBar)

      check:
        originalBarBytes.len == length
        originalBarHash == hash

suite()
