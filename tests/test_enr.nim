# Copyright (c) 2019-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/[sequtils, net],
  stew/byteutils,
  unittest2,
  ../eth/enr/enr

let rng = newRng()

func testRlpEncodingLoop(r: enr.Record): bool =
  let encoded = rlp.encode(r)
  let decoded = rlp.decode(encoded, enr.Record)
  decoded == r

suite "ENR test vector tests":
  # Tests using the test vector from:
  # https://github.com/ethereum/devp2p/blob/master/enr.md#test-vectors
  const
    uri = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8"
    pk = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"
    seqNum = 1
    id = "v4"
    ip = "7f000001"
    secp256k1 = "03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138"
    udp = 0x765f

  test "Test vector full decode - encode loop":
    let res = Record.fromURI(uri)
    check res.isOk()
    let r = res.value()
    let typedRecord = TypedRecord.fromRecord(r)
    check:
      r.seqNum == seqNum
      typedRecord.id == id
      typedRecord.ip.value() == array[4, byte].fromHex(ip)
      typedRecord.secp256k1.value() == array[33, byte].fromHex(secp256k1)
      typedRecord.udp.value() == udp
      typedRecord.tcp.isNone()

      $r == """(1, id: "v4", ip: 127.0.0.1, secp256k1: 0x03CA634CAE0D49ACB401D8A4C6B6FE8C55B70D115BF400769CC1400F3258CD3138, udp: 30303)"""

      r.toURI() == uri

  test "Test vector Record.init - encode":
    let privKey = PrivateKey.fromHex(
      pk).expect("valid private key")

    var r = Record.init(1, privKey,
      Opt.some(IpAddress(family: IPv4, address_v4: array[4, byte].fromHex(ip))),
      Opt.none(Port), Opt.some(Port(udp)))

    check:
      r.isOk()
      r.value.seqNum == seqNum
      r.value.toURI() == uri

suite "ENR encoding tests":
  test "RLP serialisation":
    let
      keypair = KeyPair.random(rng[])
      ip = parseIpAddress("1.2.3.4")
      port = Opt.some(Port(9000))
      enr = Record.init(
        100, keypair.seckey, Opt.some(ip), port, port)

    check:
      enr.isOk()
      testRlpEncodingLoop(enr.value)

  test "Empty RLP":
    expect RlpError:
      let _ = rlp.decode([], enr.Record)

    check Record.fromBytes([]).isErr()

  test "Invalid RLP":
    expect RlpError:
      let _ = rlp.decode([byte 0xf7], enr.Record)

    check Record.fromBytes([byte 0xf7]).isErr()

  test "No RLP list":
    expect RlpError:
      let _ = rlp.decode([byte 0x7f], enr.Record)

    check Record.fromBytes([byte 0x7f]).isErr()

  test "ENR with RLP list value":
    type
      RlpTestList = object
        number: uint16
        data: seq[byte]
        text: string

    let
      rlpList = RlpTestList(number: 72, data: @[byte 0x0, 0x1, 0x2], text: "Hi there")
      pk = PrivateKey.fromHex(
        "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d").expect("valid private key")
      ip = parseIpAddress("5.6.7.8")
      port = Opt.some(Port(1234))
      customPairs = [toFieldPair("some_list", rlpList)]
      enr = Record.init(
        123, pk, Opt.some(ip), Opt.none(Port), port, customPairs)

    check:
      enr.isOk()
      $enr.value == """(123, id: "v4", ip: 5.6.7.8, secp256k1: 0x02E51EFA66628CE09F689BC2B82F165A75A9DDECBB6A804BE15AC3FDF41F3B34E7, some_list: (Raw RLP list) 0xCE4883000102884869207468657265, udp: 1234)"""
      testRlpEncodingLoop(enr.value)

  test "Base64 encode loop":
    const encodedBase64 = "-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8"
    let res = Record.fromBase64(encodedBase64)
    check:
      res.isOk()
      toBase64(res.value) == encodedBase64

  test "Invalid base64":
    let res = Record.fromBase64("-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnhMHcBFZntXNFrdv*jX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8")
    check res.isErr()

  test "URI encode loop":
    let
      keypair = KeyPair.random(rng[])
      ip = parseIpAddress("1.2.3.4")
      port = Opt.some(Port(9000))
      res = Record.init(
        100, keypair.seckey, Opt.some(ip), port, port)
    check res.isOk()
    let enr = res.value()
    let uri = enr.toURI()
    let res2 = Record.fromURI(uri)
    check:
      res2.isOk()
      enr == res2.value()

  test "Invalid URI: empty":
    check Record.fromURI("").isErr()

  test "Invalid URI: no payload":
    check Record.fromURI("enr:").isErr()

suite "ENR init tests":
  test "Record.init minimum fields":
    let
      keypair = KeyPair.random(rng[])
      port = Opt.none(Port)
      enr = Record.init(
        100, keypair.seckey, Opt.none(IpAddress), port, port)[]
      typedEnr = TypedRecord.fromRecord(enr)

    check:
      testRlpEncodingLoop(enr)

      typedEnr.secp256k1.isSome()
      typedEnr.secp256k1.get() == keypair.pubkey.toRawCompressed()

      typedEnr.ip.isNone()
      typedEnr.tcp.isNone()
      typedEnr.udp.isNone()

      typedEnr.ip6.isNone()
      typedEnr.tcp6.isNone()
      typedEnr.udp6.isNone()

  test "Record.init only ipv4":
    let
      keypair = KeyPair.random(rng[])
      ip = parseIpAddress("1.2.3.4")
      port = Opt.some(Port(9000))
      enr = Record.init(
        100, keypair.seckey, Opt.some(ip), port, port)[]
      typedEnr = TypedRecord.fromRecord(enr)

    check:
      typedEnr.ip.isSome()
      typedEnr.ip.get() == [byte 1, 2, 3, 4]

      typedEnr.tcp.isSome()
      typedEnr.tcp.get() == 9000

      typedEnr.udp.isSome()
      typedEnr.udp.get() == 9000

  test "Record.init only ipv6":
    let
      keypair = KeyPair.random(rng[])
      ip = parseIpAddress("::1")
      port = Opt.some(Port(9000))
      enr = Record.init(
        100, keypair.seckey, Opt.some(ip), port, port)[]
      typedEnr = TypedRecord.fromRecord(enr)

    check:
      typedEnr.ip.isNone()
      typedEnr.tcp.isSome()
      typedEnr.tcp.value() == 9000
      typedEnr.udp.isSome()
      typedEnr.udp.value() == 9000

      typedEnr.ip6.isSome()
      typedEnr.ip6.get() == [byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]

      typedEnr.tcp6.isNone()
      typedEnr.udp6.isNone()

  test "Record.init max ENR size":
    let
      pk = PrivateKey.fromHex(
      "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d").expect("valid private key")
    block: # This gives ENR of 300 bytes encoded
      let r = Record.init(
        1, pk, extraFields = [toFieldPair("maxvalue", repeat(byte 2, 169))]
      )
      check r.isOk()

    block: # This gives ENR of 301 bytes encoded
      let r = Record.init(
        1, pk, extraFields = [toFieldPair("maxplus1", repeat(byte 2, 170))]
      )
      check r.isErr()

  test "PreDefinedKeys in custom pairs":
    let
      keypair = KeyPair.random(rng[])
      customPairs = [toFieldPair("ip", @[byte 1, 1, 1, 1])]

    expect AssertionDefect:
      let _ = Record.init(
        1, keypair.seckey, extraFields = customPairs)

  test "Duplicate key":
    # With duplicate key, the last one should be used (insert)
    let
      keypair = KeyPair.random(rng[])
      customPairs = [
        toFieldPair("test1", @[byte 1, 1, 1, 1]),
        toFieldPair("test2", "abc"),
        toFieldPair("test1", "1.2.3.4")
      ]

    let res = Record.init(
        1, keypair.seckey, extraFields = customPairs)

    check: res.isOk()
    let
      enr = res.value
      test1Field = enr.get("test1", string)
      test2Field = enr.get("test2", string)
    check:
      test1Field.isOk()
      test2Field.isOk()
      test1Field.value == "1.2.3.4"
      test2Field.value == "abc"

  test "Record.init sorted":
    let
      pk = PrivateKey.fromHex(
        "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d").expect("valid private key")
      customPairs = [
        toFieldPair("abc", 1234'u),
        toFieldPair("z", [byte 0]),
        toFieldPair("123", "abc"),
        toFieldPair("a12", 1'u)
      ]
      r = Record.init(123, pk, extraFields = customPairs)

    check:
      r.isOk()
      $r.value == """(123, 123: "abc", a12: 1, abc: 1234, id: "v4", secp256k1: 0x02E51EFA66628CE09F689BC2B82F165A75A9DDECBB6A804BE15AC3FDF41F3B34E7, z: 0x00)"""

suite "ENR update tests":
  test "ENR update":
    let
      pk = PrivateKey.fromHex(
        "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d")[]
      newField = toFieldPair("test", 123'u)
    var r = Record.init(1, pk, Opt.none(IpAddress), Opt.none(Port), Opt.none(Port))[]

    block: # Insert new k:v pair, update of seqNum should occur.
      let updated = r.update(pk, extraFields = [newField])
      check updated.isOk()
      check:
        r.get("test", uint).get() == 123
        r.seqNum == 2

    block: # Insert same k:v pair, update of seqNum still occurs.
      let updated = r.update(pk, extraFields = [newField])
      check updated.isOk()
      check:
        r.get("test", uint).get() == 123
        r.seqNum == 3

    block: # Insert k:v pair with changed value, update of seqNum should occur.
      let updatedField = toFieldPair("test", 1234'u)
      let updated = r.update(pk, extraFields = [updatedField])
      check updated.isOk()
      check:
        r.get("test", uint).get() == 1234
        r.seqNum == 4

  test "ENR update sorted":
    let
      pk = PrivateKey.fromHex(
        "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d").expect("valid private key")
      customPairs = [
        toFieldPair("abc", 1234'u),
        toFieldPair("z", [byte 0]),
        toFieldPair("123", "abc"),
        toFieldPair("a12", 1'u)
      ]
      res = Record.init(123, pk, extraFields = customPairs)

    check res.isOk()
    var r = res.value

    check $r == """(123, 123: "abc", a12: 1, abc: 1234, id: "v4", secp256k1: 0x02E51EFA66628CE09F689BC2B82F165A75A9DDECBB6A804BE15AC3FDF41F3B34E7, z: 0x00)"""

    let newField = toFieldPair("test", 123'u)
    let newField2 = toFieldPair("zzz", 123'u)
    let updated = r.update(pk, extraFields = [newField, newField2])
    check updated.isOk()
    check $r == """(124, 123: "abc", a12: 1, abc: 1234, id: "v4", secp256k1: 0x02E51EFA66628CE09F689BC2B82F165A75A9DDECBB6A804BE15AC3FDF41F3B34E7, test: 123, z: 0x00, zzz: 123)"""

  test "ENR update too large":
    let
      pk = PrivateKey.fromHex(
        "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d").expect("valid private key")
      customPairs = [toFieldPair("maxvalue", repeat(byte 2, 169))]

      res = Record.init(123, pk, extraFields = customPairs)

    check res.isOk()
    var r = res.value

    let newField = toFieldPair("test", 123'u)
    let updated = r.update(pk, extraFields = [newField])
    check updated.isErr()

  test "ENR update with wrong private key":
    let
      pk = PrivateKey.fromHex(
        "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d").expect("valid private key")

      res = Record.init(123, pk)
    check res.isOk()
    var r = res.value

    let
      wrongPk = PrivateKey.random(rng[])
      newField = toFieldPair("test", 123'u)
      updated = r.update(wrongPk, extraFields = [newField])
    check updated.isErr()

  test "ENR update addresses":
    let
      pk = PrivateKey.fromHex(
        "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d")[]
    var r = Record.init(1, pk, Opt.none(IpAddress),
      Opt.some(Port(9000)), Opt.some(Port(9000)))[]

    block:
      let updated = r.update(pk, Opt.none(IpAddress),
        Opt.some(Port(9000)), Opt.some(Port(9000)))
      check updated.isOk()
      check:
        r.tryGet("ip", uint).isNone()
        r.tryGet("tcp", uint).isSome()
        r.tryGet("udp", uint).isSome()
        r.seqNum == 2

    block:
      let updated = r.update(pk, Opt.none(IpAddress),
        Opt.some(Port(9001)), Opt.some(Port(9002)))
      check updated.isOk()
      check:
        r.tryGet("ip", uint).isNone()
        r.tryGet("tcp", uint).isSome()
        r.tryGet("udp", uint).isSome()
        r.seqNum == 3

    block:
      let updated = r.update(pk, Opt.some(parseIpAddress("10.20.30.40")),
        Opt.some(Port(9000)), Opt.some(Port(9000)))
      check updated.isOk()

      let typedEnr = TypedRecord.fromRecord(r)

      check:
        typedEnr.ip.isSome()
        typedEnr.ip.get() == [byte 10, 20, 30, 40]

        typedEnr.tcp.isSome()
        typedEnr.tcp.get() == 9000

        typedEnr.udp.isSome()
        typedEnr.udp.get() == 9000

        r.seqNum == 4

    block:
      let updated = r.update(pk, Opt.some(parseIpAddress("1.2.3.4")),
        Opt.some(Port(9001)), Opt.some(Port(9001)))
      check updated.isOk()

      let typedEnr = TypedRecord.fromRecord(r)

      check:
        typedEnr.ip.isSome()
        typedEnr.ip.get() == [byte 1, 2, 3, 4]

        typedEnr.tcp.isSome()
        typedEnr.tcp.get() == 9001

        typedEnr.udp.isSome()
        typedEnr.udp.get() == 9001

        r.seqNum == 5
