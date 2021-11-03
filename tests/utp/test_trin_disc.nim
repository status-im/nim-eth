import
  chronos, bearssl,
  stew/shims/net, stew/byteutils,
  testutils/unittests,
  ../../eth/p2p/discoveryv5/[enr, node, routing_table],
  ../../eth/p2p/discoveryv5/protocol as discv5_protocol,
  ../../eth/utp/utp_router,
  ../../eth/utp/utp_discov5_protocol,
  ../../eth/keys

proc registerIncomingSocketCallback(serverSockets: AsyncQueue): AcceptConnectionCallback[Node] =
  return (
    proc(server: UtpRouter[Node], client: UtpSocket[Node]): Future[void] =
      serverSockets.addLast(client)
  )

proc initDiscoveryNode*(rng: ref BrHmacDrbgContext,
    privKey: PrivateKey,
    address: Address,
    bootstrapRecords: openarray[Record] = [],
    localEnrFields: openarray[(string, seq[byte])] = [],
    previousRecord = none[enr.Record]()): discv5_protocol.Protocol =
  # set bucketIpLimit to allow bucket split
  let tableIpLimits = TableIpLimits(tableIpLimit: 1000,  bucketIpLimit: 24)

  result = newProtocol(privKey,
    some(address.ip),
    some(address.port), some(address.port),
    bindPort = address.port,
    bootstrapRecords = bootstrapRecords,
    localEnrFields = localEnrFields,
    previousRecord = previousRecord,
    tableIpLimits = tableIpLimits,
    rng = rng)

  result.open()

proc localAddress*(port: int): Address =
  Address(ip: ValidIpAddress.init("127.0.0.1"), port: Port(port))

let rng = newRng()
let utpProtId = "utp".toBytes()

let
  queue = newAsyncQueue[UtpSocket[Node]]()
  node1 = initDiscoveryNode(rng, PrivateKey.random(rng[]), localAddress(20302))
  utp1 = UtpDiscv5Protocol.new(node1, utpProtId, registerIncomingSocketCallback(queue))

# It requires trin node enr
let remoteEnr = "-IS4QGcN14I-ABqrPyXIfWlfU1qX51Iq9PDtDqg3AODMEYIRIUURYVyLEZwpVeNk5pv51lKOZywwlH6y6Wf2GfxTLOABgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQK3JxwdIu-BoNDCx4Dv3EM9v0hi0vW1Z27XM3dVjnckfYN1ZHCCJpQ"

var rec = Record()
let res = rec.fromBase64(remoteEnr)
let nodeInfo = newNode(rec).get()
discard node1.addNode(nodeInfo)
echo rec
discard waitFor node1.ping(nodeInfo)
let socket = waitFor utp1.connectTo(nodeInfo)
let dataToSend = @[1'u8, 2, 3, 4, 5, 6]
echo "Before data write"
let written = waitFor socket.write(dataToSend)
echo "send " & $written & " bytes"
waitFor sleepAsync(seconds(5))

waitFor(node1.closeWait())
