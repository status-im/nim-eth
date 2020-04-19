import
  net, unittest, options,
  nimcrypto/utils,
  eth/p2p/enode, eth/p2p/discoveryv5/enr, eth/keys

suite "ENR":
  test "Serialization":
    var pk = PrivateKey.fromHex(
      "5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d")[]
    var r = initRecord(123, pk, {"udp": 1234'u, "ip": [byte 5, 6, 7, 8]})
    doAssert($r == """(id: "v4", ip: 0x05060708, secp256k1: 0x02E51EFA66628CE09F689BC2B82F165A75A9DDECBB6A804BE15AC3FDF41F3B34E7, udp: 1234)""")
    let uri = r.toURI()
    var r2: Record
    let sigValid = r2.fromURI(uri)
    doAssert(sigValid)
    doAssert($r2 == $r)

  test "Parsing":
    var r: Record
    let sigValid = r.fromBase64("-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8")
    doAssert(sigValid)
    doAssert($r == """(id: "v4", ip: 0x7F000001, secp256k1: 0x03CA634CAE0D49ACB401D8A4C6B6FE8C55B70D115BF400769CC1400F3258CD3138, udp: 30303)""")

  test "Bad base64":
    var r: Record
    let sigValid = r.fromURI("enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnhMHcBFZntXNFrdv*jX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8")
    doAssert(not sigValid)

  test "Bad rlp":
    var r: Record
    let sigValid = r.fromBase64("-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOOnrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8")
    doAssert(not sigValid)

  test "Create from ENode address":
    let
      keys = KeyPair.random()[]
      ip = parseIpAddress("10.20.30.40")
      enr = Record.init(100, keys.seckey, some(ip), Port(9000), Port(9000), @[])
      typedEnr = get enr.toTypedRecord()

    check:
      typedEnr.secp256k1.isSome()
      typedEnr.secp256k1.get == keys.pubkey.toRawCompressed()

      typedEnr.ip.isSome()
      typedEnr.ip.get() == [byte 10, 20, 30, 40]

      typedEnr.tcp.isSome()
      typedEnr.tcp.get() == 9000

      typedEnr.udp.isSome()
      typedEnr.udp.get() == 9000

  test "ENR without address":
    let
      keys = KeyPair.random()[]
      enr = Record.init(100, keys.seckey, none(IpAddress), Port(9000), Port(9000))
      typedEnr = get enr.toTypedRecord()

    check:
      typedEnr.secp256k1.isSome()
      typedEnr.secp256k1.get() == keys.pubkey.toRawCompressed()

      typedEnr.ip.isNone()
      typedEnr.tcp.isSome()
      typedEnr.tcp.get() == 9000

      typedEnr.udp.isSome()
      typedEnr.udp.get() == 9000

      typedEnr.ip6.isNone()
      typedEnr.tcp6.isNone()
      typedEnr.udp6.isNone()
