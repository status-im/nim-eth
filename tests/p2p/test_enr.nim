import unittest
import eth/p2p/discoveryv5/enr, eth/keys

suite "ENR":
  test "Serialization":
    var pk = initPrivateKey("5d2908f3f09ea1ff2e327c3f623159639b00af406e9009de5fd4b910fc34049d")
    var r = initRecord(123, pk, {"udp": 1234, "ip": 12345})
    doAssert($r == """(id: "v4", ip: 12345, secp256k1: 0x02E51EFA66628CE09F689BC2B82F165A75A9DDECBB6A804BE15AC3FDF41F3B34E7, udp: 1234)""")
    let uri = r.toURI()
    var r2: Record
    let sigValid = r2.fromURI(uri)
    doAssert(sigValid)
    doAssert($r2 == $r)

  test "Parsing":
    var r: Record
    let sigValid = r.fromBase64("-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8")
    doAssert(sigValid)
    doAssert($r == """(id: "v4", ip: 2130706433, secp256k1: 0x03CA634CAE0D49ACB401D8A4C6B6FE8C55B70D115BF400769CC1400F3258CD3138, udp: 30303)""")

  test "Bad base64":
    var r: Record
    let sigValid = r.fromURI("enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnhMHcBFZntXNFrdv*jX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8")
    doAssert(not sigValid)

  test "Bad rlp":
    var r: Record
    let sigValid = r.fromBase64("-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOOnrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8")
    doAssert(not sigValid)
