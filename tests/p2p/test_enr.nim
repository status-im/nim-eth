# Copyright (c) 2019-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/[options, sequtils],
  unittest2,
  stew/shims/net,
  ../../eth/p2p/discoveryv5/enr, ../../eth/[keys, rlp]

let rng = newRng()

suite "ENR":
  test "Serialization":
    var pk = PrivateKey.fromHex(
      "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d")[]
    var r = initRecord(123, pk, {"udp": 1234'u, "ip": [byte 5, 6, 7, 8]})[]
    check($r == """(123, id: "v4", ip: 5.6.7.8, secp256k1: 0x02E51EFA66628CE09F689BC2B82F165A75A9DDECBB6A804BE15AC3FDF41F3B34E7, udp: 1234)""")
    let uri = r.toURI()
    var r2: Record
    let sigValid = r2.fromURI(uri)
    check(sigValid)
    check($r2 == $r)
    check(r2.raw == r.raw)

  test "RLP serialisation":
    var pk = PrivateKey.fromHex(
      "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d")[]
    var r = initRecord(123, pk, {"udp": 1234'u, "ip": [byte 5, 6, 7, 8]})[]
    check($r == """(123, id: "v4", ip: 5.6.7.8, secp256k1: 0x02E51EFA66628CE09F689BC2B82F165A75A9DDECBB6A804BE15AC3FDF41F3B34E7, udp: 1234)""")
    let encoded = rlp.encode(r)
    let decoded = rlp.decode(encoded, enr.Record)
    check($decoded == $r)
    check(decoded.raw == r.raw)

  test "RLP deserialisation without data":
    expect ValueError:
      let decoded = rlp.decode([], enr.Record)

    var r: Record
    check not fromBytes(r, [])

  test "Base64 deserialisation without data":
    var r: Record
    let sigValid = r.fromURI("enr:")
    check(not sigValid)

  test "Parsing":
    var r: Record
    let sigValid = r.fromBase64("-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8")
    check(sigValid)
    check($r == """(1, id: "v4", ip: 127.0.0.1, secp256k1: 0x03CA634CAE0D49ACB401D8A4C6B6FE8C55B70D115BF400769CC1400F3258CD3138, udp: 30303)""")

  test "Bad base64":
    var r: Record
    let sigValid = r.fromURI("enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnhMHcBFZntXNFrdv*jX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8")
    check(not sigValid)

  test "Bad rlp":
    var r: Record
    let sigValid = r.fromBase64("-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOOnrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8")
    check(not sigValid)

  test "Create from ENode address":
    let
      keypair = KeyPair.random(rng[])
      ip = ValidIpAddress.init("10.20.30.40")
      port = some(Port(9000))
      enr = Record.init(
        100, keypair.seckey, some(ip), port, port,@[])[]
      typedEnr = get enr.toTypedRecord()

    check:
      typedEnr.secp256k1.isSome()
      typedEnr.secp256k1.get == keypair.pubkey.toRawCompressed()

      typedEnr.ip.isSome()
      typedEnr.ip.get() == [byte 10, 20, 30, 40]

      typedEnr.tcp.isSome()
      typedEnr.tcp.get() == 9000

      typedEnr.udp.isSome()
      typedEnr.udp.get() == 9000

  test "ENR without address":
    let
      keypair = KeyPair.random(rng[])
      port = none(Port)
      enr = Record.init(
        100, keypair.seckey, none(ValidIpAddress), port, port)[]
      typedEnr = get enr.toTypedRecord()

    check:
      typedEnr.secp256k1.isSome()
      typedEnr.secp256k1.get() == keypair.pubkey.toRawCompressed()

      typedEnr.ip.isNone()
      typedEnr.tcp.isNone()
      typedEnr.udp.isNone()

      typedEnr.ip6.isNone()
      typedEnr.tcp6.isNone()
      typedEnr.udp6.isNone()

  test "ENR init size too big":
    let pk = PrivateKey.fromHex(
      "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d")[]
    block: # This gives ENR of 300 bytes encoded
      let r = initRecord(1, pk, {"maxvalue": repeat(byte 2, 169),})
      check r.isOk()

    block: # This gives ENR of 301 bytes encoded
      let r = initRecord(1, pk, {"maxplus1": repeat(byte 2, 170),})
      check r.isErr()

  test "ENR update":
    let
      pk = PrivateKey.fromHex(
        "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d")[]
      newField = toFieldPair("test", 123'u)
    var r = Record.init(1, pk, none(ValidIpAddress), none(Port), none(Port))[]

    block: # Insert new k:v pair, update of seqNum should occur.
      let updated = r.update(pk, [newField])
      check updated.isOk()
      check:
        r.get("test", uint).get() == 123
        r.seqNum == 2

    block: # Insert same k:v pair, no update of seqNum should occur.
      let updated = r.update(pk, [newField])
      check updated.isOk()
      check:
        r.get("test", uint).get() == 123
        r.seqNum == 2

    block: # Insert k:v pair with changed value, update of seqNum should occur.
      let updatedField = toFieldPair("test", 1234'u)
      let updated = r.update(pk, [updatedField])
      check updated.isOk()
      check:
        r.get("test", uint).get() == 1234
        r.seqNum == 3

  test "ENR update sorted":
    let pk = PrivateKey.fromHex(
      "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d")[]
    var r = initRecord(123, pk, {"abc": 1234'u,
                                 "z": [byte 0],
                                 "123": "abc",
                                 "a12": 1'u})[]
    check $r == """(123, 123: "abc", a12: 1, abc: 1234, id: "v4", secp256k1: 0x02E51EFA66628CE09F689BC2B82F165A75A9DDECBB6A804BE15AC3FDF41F3B34E7, z: 0x00)"""

    let newField = toFieldPair("test", 123'u)
    let newField2 = toFieldPair("zzz", 123'u)
    let updated = r.update(pk, [newField, newField2])
    check updated.isOk()
    check $r == """(124, 123: "abc", a12: 1, abc: 1234, id: "v4", secp256k1: 0x02E51EFA66628CE09F689BC2B82F165A75A9DDECBB6A804BE15AC3FDF41F3B34E7, test: 123, z: 0x00, zzz: 123)"""

  test "ENR update size too big":
    let pk = PrivateKey.fromHex(
      "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d")[]

    var r = initRecord(1, pk, {"maxvalue": repeat(byte 2, 169),})
    check r.isOk()

    let newField = toFieldPair("test", 123'u)
    let updated = r[].update(pk, [newField])
    check updated.isErr()

  test "ENR update invalid key":
    let pk = PrivateKey.fromHex(
      "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d")[]

    var r = initRecord(1, pk, {"abc": 1'u,})
    check r.isOk()

    let
      wrongPk = PrivateKey.random(rng[])
      newField = toFieldPair("test", 123'u)
      updated = r[].update(wrongPk, [newField])
    check updated.isErr()

  test "ENR update address":
    let
      pk = PrivateKey.fromHex(
        "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d")[]
    var r = Record.init(1, pk, none(ValidIpAddress),
      some(Port(9000)), some(Port(9000)))[]

    block:
      let updated = r.update(pk, none(ValidIpAddress),
        some(Port(9000)), some(Port(9000)))
      check updated.isOk()
      check:
        r.tryGet("ip", uint).isNone()
        r.tryGet("tcp", uint).isSome()
        r.tryGet("udp", uint).isSome()
        r.seqNum == 1

    block:
      let updated = r.update(pk, none(ValidIpAddress),
        some(Port(9001)), some(Port(9002)))
      check updated.isOk()
      check:
        r.tryGet("ip", uint).isNone()
        r.tryGet("tcp", uint).isSome()
        r.tryGet("udp", uint).isSome()
        r.seqNum == 2

    block:
      let updated = r.update(pk, some(ValidIpAddress.init("10.20.30.40")),
        some(Port(9000)), some(Port(9000)))
      check updated.isOk()

      let typedEnr = r.toTypedRecord().get()

      check:
        typedEnr.ip.isSome()
        typedEnr.ip.get() == [byte 10, 20, 30, 40]

        typedEnr.tcp.isSome()
        typedEnr.tcp.get() == 9000

        typedEnr.udp.isSome()
        typedEnr.udp.get() == 9000

        r.seqNum == 3

    block:
      let updated = r.update(pk, some(ValidIpAddress.init("10.20.30.40")),
        some(Port(9001)), some(Port(9001)))
      check updated.isOk()

      let typedEnr = r.toTypedRecord().get()

      check:
        typedEnr.ip.isSome()
        typedEnr.ip.get() == [byte 10, 20, 30, 40]

        typedEnr.tcp.isSome()
        typedEnr.tcp.get() == 9001

        typedEnr.udp.isSome()
        typedEnr.udp.get() == 9001

        r.seqNum == 4

  test "ENR with RLP list value":
    type
      RlpTestList = object
        number: uint16
        data: seq[byte]
        text: string

    let rlpList =
      RlpTestList(number: 72, data: @[byte 0x0, 0x1, 0x2], text: "Hi there")

    let pk = PrivateKey.fromHex(
      "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d")[]
    var r = initRecord(123, pk, {"udp": 1234'u, "ip": [byte 5, 6, 7, 8],
      "some_list": rlpList})[]

    check($r == """(123, id: "v4", ip: 5.6.7.8, secp256k1: 0x02E51EFA66628CE09F689BC2B82F165A75A9DDECBB6A804BE15AC3FDF41F3B34E7, some_list: (Raw RLP list) 0xCE4883000102884869207468657265, udp: 1234)""")

    let encoded = rlp.encode(r)
    let decoded = rlp.decode(encoded, enr.Record)
    check($decoded == $r)
    check(decoded.raw == r.raw)

  test "ENR IP addresses ":
    let pk = PrivateKey.fromHex(
      "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d")[]
    block: # valid ipv4
      var r = initRecord(123, pk, {"udp": 1234'u, "ip": [byte 5, 6, 7, 8]})[]

      check($r == """(123, id: "v4", ip: 5.6.7.8, secp256k1: 0x02E51EFA66628CE09F689BC2B82F165A75A9DDECBB6A804BE15AC3FDF41F3B34E7, udp: 1234)""")

      let encoded = rlp.encode(r)
      let decoded = rlp.decode(encoded, enr.Record)
      check($decoded == $r)
      check(decoded.raw == r.raw)

    block: # invalid ipv4
      var r = initRecord(123, pk, {"udp": 1234'u, "ip": [byte 5, 6, 7]})[]

      check($r == """(123, id: "v4", ip: (Invalid) 0x050607, secp256k1: 0x02E51EFA66628CE09F689BC2B82F165A75A9DDECBB6A804BE15AC3FDF41F3B34E7, udp: 1234)""")

      let encoded = rlp.encode(r)
      let decoded = rlp.decode(encoded, enr.Record)
      check($decoded == $r)
      check(decoded.raw == r.raw)

    block: # valid ipv4 + ipv6
      var r = initRecord(123, pk, {"udp": 1234'u, "ip": [byte 5, 6, 7, 8],
        "ip6": [byte 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6]})[]

      check($r == """(123, id: "v4", ip: 5.6.7.8, ip6: 102::102:304:506, secp256k1: 0x02E51EFA66628CE09F689BC2B82F165A75A9DDECBB6A804BE15AC3FDF41F3B34E7, udp: 1234)""")

      let encoded = rlp.encode(r)
      let decoded = rlp.decode(encoded, enr.Record)
      check($decoded == $r)
      check(decoded.raw == r.raw)

    block: # invalid ipv4 + ipv6
      var r = initRecord(123, pk, {"udp": 1234'u, "ip": [byte 5, 6, 7, 8, 9],
        "ip6": [byte 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5]})[]

      check($r == """(123, id: "v4", ip: (Invalid) 0x0506070809, ip6: (Invalid) 0x010200000000000000000102030405, secp256k1: 0x02E51EFA66628CE09F689BC2B82F165A75A9DDECBB6A804BE15AC3FDF41F3B34E7, udp: 1234)""")

      let encoded = rlp.encode(r)
      let decoded = rlp.decode(encoded, enr.Record)
      check($decoded == $r)
      check(decoded.raw == r.raw)
