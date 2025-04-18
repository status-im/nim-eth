{.used.}

import
  std/times,
  unittest2,
  stew/byteutils,
  ../../eth/rlp,
  ../../eth/common/hashes

type
  Transaction = object
    amount: uint64
    time: uint64
    sender: string
    receiver: string

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

rlpFields Foo,
  x, y, z

rlpFields Transaction,
  sender, receiver, amount

proc append*(rlpWriter: var RlpWriter, holder: CustomSerialized, f: Foo) =
  rlpWriter.append(f.x)
  rlpWriter.append(uint64 f.y.len)
  rlpWriter.append(holder.ignored)

proc read*(rlp: var Rlp, holder: var CustomSerialized, T: type Foo): Foo =
  result.x = rlp.read(uint64)
  result.y = newString(rlp.read(uint64))
  holder.ignored = rlp.read(uint64) * 2

proc suite() =
  suite "object serialization":
    test "encoding and decoding an object":
      var originalBar = Bar(b: "abracadabra",
                            f: Foo(x: 5'u64, y: "hocus pocus", z: @[uint64 100, 200, 300]))

      var bytes = encode(originalBar)
      var r = rlpFromBytes(bytes)
      var restoredBar = r.read(Bar)

      check:
        originalBar == restoredBar

      var t1 = Transaction(time: 100, amount: 1000, sender: "Alice", receiver: "Bob")
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
