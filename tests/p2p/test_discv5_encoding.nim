import unittest
import eth/p2p/discoveryv5/[types, encoding, enr]
import eth/rlp, stew/byteutils

# According to test vectors:
# https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md

suite "Discovery v5 Protocol Message Encodings":
  test "Ping Request":
    var p: PingPacket
    p.enrSeq = 1
    var reqId: RequestId = 1
    check encodePacket(p, reqId).toHex == "01c20101"

  test "Pong Response":
    var p: PongPacket
    p.enrSeq = 1
    p.port = 5000
    p.ip = @[127.byte, 0, 0, 1]
    var reqId: RequestId = 1
    check encodePacket(p, reqId).toHex == "02ca0101847f000001821388"

  test "FindNode Request":
    var p: FindNodePacket
    p.distance = 0x0100
    var reqId: RequestId = 1
    check encodePacket(p, reqId).toHex == "03c401820100"

  test "Nodes Response (empty)":
    var p: NodesPacket
    p.total = 0x1
    var reqId: RequestId = 1
    check encodePacket(p, reqId).toHex == "04c30101c0"

  test "Nodes Response (multiple)":
    var p: NodesPacket
    p.total = 0x1
    var e1, e2: Record
    check e1.fromURI("enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg")
    check e2.fromURI("enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU")

    p.enrs = @[e1, e2]
    var reqId: RequestId = 1
    check encodePacket(p, reqId).toHex == "04f8f20101f8eef875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235"
