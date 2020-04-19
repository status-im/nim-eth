import
  chronos, times, stew/byteutils, stint, chronicles, streams, nimcrypto, os,
  strformat, strutils, eth/p2p/[discovery, kademlia], eth/[keys, rlp],
  ../../p2p/p2p_test_helper

template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]
const inputsDir = &"{sourceDir}{DirSep}generated-input{DirSep}"

proc toFile(data: Bytes, fn: string) =
  var s = newFileStream(fn, fmWrite)
  for x in data:
    s.write(x)
  s.close()

const EXPIRATION = 3600 * 24 * 365 * 10
proc expiration(): uint32 = uint32(epochTime() + EXPIRATION)

proc generate() =
  ## Generate some valid inputs where one can start fuzzing with
  let
    fromAddr = localAddress(30303)
    toAddr = localAddress(30304)
    peerKey = PrivateKey.fromHex("a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a617")[]

  # valid data for a Ping packet
  block:
    let payload = rlp.encode((4, fromAddr, toAddr, expiration()))
    let encodedData = @[1.byte] & payload
    debug "Ping", data=byteutils.toHex(encodedData)

    encodedData.toFile(inputsDir & "ping")

  # valid data for a Pong packet
  block:
    let token = keccak256.digest(@[0])
    let payload = rlp.encode((toAddr, token , expiration()))
    let encodedData = @[2.byte] & payload
    debug "Pong", data=byteutils.toHex(encodedData)

    encodedData.toFile(inputsDir & "pong")

  # valid data for a FindNode packet
  block:
    var data: array[64, byte]
    data[32 .. ^1] = peerKey.toPublicKey().tryGet().toNodeId().toByteArrayBE()
    let payload = rlp.encode((data, expiration()))
    let encodedData = @[3.byte] & payload.toSeq()
    debug "FindNode", data=byteutils.toHex(encodedData)

    encodedData.toFile(inputsDir & "findnode")

  # valid data for a Neighbours packet
  block:
    let
      n1Addr = localAddress(30305)
      n2Addr = localAddress(30306)
      n1Key = PrivateKey.fromHex(
        "a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a618")[]
      n2Key = PrivateKey.fromHex(
        "a2b50376a79b1a8c8a3296485572bdfbf54708bb46d3c25d73d2723aaaf6a619")[]

    type Neighbour = tuple[ip: IpAddress, udpPort, tcpPort: Port, pk: PublicKey]
    var nodes = newSeqOfCap[Neighbour](2)

    nodes.add((n1Addr.ip, n1Addr.udpPort, n1Addr.tcpPort, n1Key.toPublicKey().tryGet()))
    nodes.add((n2Addr.ip, n2Addr.udpPort, n2Addr.tcpPort, n2Key.toPublicKey().tryGet()))

    let payload = rlp.encode((nodes, expiration()))
    let encodedData = @[4.byte] & payload.toSeq()
    debug "Neighbours", data=byteutils.toHex(encodedData)

    encodedData.toFile(inputsDir & "neighbours")

discard existsOrCreateDir(inputsDir)
generate()
