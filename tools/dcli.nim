# Copyright (c) 2020-2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

{.push raises: [].}

import
  std/[strutils, sets],
  confutils, confutils/std/net, chronicles, chronicles/topics_registry,
  chronos, metrics, metrics/chronos_httpserver,
  stew/[byteutils, bitops2],
  ../eth/keys, ../eth/net/nat,
  ../eth/common/hashes,
  ../eth/p2p/discoveryv5/[enr, node],
  ../eth/p2p/discoveryv5/protocol as discv5_protocol

const
  defaultListenAddress* = (static parseIpAddress("0.0.0.0"))
  defaultAdminListenAddress* = (static parseIpAddress("127.0.0.1"))
  defaultListenAddressDesc = $defaultListenAddress
  defaultAdminListenAddressDesc = $defaultAdminListenAddress

type
  DiscoveryCmd* = enum
    noCommand
    ping
    findNode
    talkReq
    generateKeys

  DiscoveryConf* = object
    logLevel* {.
      defaultValue: LogLevel.DEBUG
      desc: "Sets the log level"
      name: "log-level" .}: LogLevel

    udpPort* {.
      defaultValue: 9009
      desc: "UDP listening port"
      name: "udp-port" .}: uint16

    listenAddress* {.
      defaultValue: defaultListenAddress
      defaultValueDesc: $defaultListenAddressDesc
      desc: "Listening address for the Discovery v5 traffic"
      name: "listen-address" }: IpAddress

    persistingFile* {.
      defaultValue: "peerstore.csv",
      desc: "File path where discovered nodes and their ENRs will be stored",
      name: "persisting-file" .}: string

    bootstrapNodes* {.
      desc:
        "ENR URI of node to bootstrap Discovery v5 network from. Argument may be repeated",
      name: "bootstrap-node"
    .}: seq[enr.Record]

    nat* {.
      desc: "Specify method to use for determining public address. " &
            "Must be one of: any, none, upnp, pmp, extip:<IP>"
      defaultValue: NatConfig(hasExtIp: false, nat: NatAny)
      name: "nat" .}: NatConfig

    enrAutoUpdate* {.
      defaultValue: false
      desc: "Discovery can automatically update its ENR with the IP address " &
            "and UDP port as seen by other nodes it communicates with. " &
            "This option allows to enable/disable this functionality"
      name: "enr-auto-update" .}: bool

    nodeKey* {.
      desc: "P2P node private key as hex",
      defaultValue: PrivateKey.random(keys.newRng()[])
      name: "nodekey" .}: PrivateKey

    metricsEnabled* {.
      defaultValue: false
      desc: "Enable the metrics server"
      name: "metrics" .}: bool

    metricsAddress* {.
      defaultValue: defaultAdminListenAddress
      defaultValueDesc: $defaultAdminListenAddressDesc
      desc: "Listening address of the metrics server"
      name: "metrics-address" .}: IpAddress

    metricsPort* {.
      defaultValue: 8008
      desc: "Listening HTTP port of the metrics server"
      name: "metrics-port" .}: Port

    case cmd* {.
      command
      defaultValue: noCommand }: DiscoveryCmd
    of noCommand:
      discard
    of ping:
      pingTarget* {.
        argument
        desc: "ENR URI of the node to a send ping message"
        name: "node" .}: Node
    of findNode:
      distance* {.
        defaultValue: 255
        desc: "Distance parameter for the findNode message"
        name: "distance" .}: uint16
      # TODO: Order here matters as else the help message does not show all the
      # information, see: https://github.com/status-im/nim-confutils/issues/15
      findNodeTarget* {.
        argument
        desc: "ENR URI of the node to send a findNode message"
        name: "node" .}: Node
    of talkReq:
      talkReqTarget* {.
        argument
        desc: "ENR URI of the node to send a talkReq message"
        name: "node" .}: Node
    of generateKeys:
      numKeys* {.
        argument
        desc: "Number of evenly distributed keys to generate"
        name: "n" .}: uint16

proc parseCmdArg*(T: type enr.Record, p: string): T {.raises: [ValueError].} =
  let res = enr.Record.fromURI(p)
  if res.isErr:
    raise newException(ValueError, "Invalid ENR:" & $res.error)

  res.value

proc completeCmdArg*(T: type enr.Record, val: string): seq[string] =
  return @[]

proc parseCmdArg*(T: type Node, p: string): T {.raises: [ValueError].} =
  let res = enr.Record.fromURI(p)
  if res.isErr:
    raise newException(ValueError, "Invalid ENR:" & $res.error)

  let n = Node.fromRecord(res.value)
  if n.address.isNone():
    raise newException(ValueError, "ENR without address")

  n

proc completeCmdArg*(T: type Node, val: string): seq[string] =
  return @[]

proc parseCmdArg*(T: type PrivateKey, p: string): T {.raises: [ValueError].} =
  try:
    result = PrivateKey.fromHex(p).tryGet()
  except CatchableError:
    raise newException(ValueError, "Invalid private key")

proc completeCmdArg*(T: type PrivateKey, val: string): seq[string] =
  return @[]

proc generateDistributedNetKeys(
    rng: var HmacDrbgContext, n: uint16
): seq[PrivateKey] =
  ## Generate n network keys evenly distributed over the node id keyspace.
  ## Limited to only 2-byte precision
  var res = newSeq[PrivateKey](n)

  if n == 1:
    res[0] = PrivateKey.random(rng)
    return res

  let stepSize = 65536 div n

  for i in 0..<n.uint:
    let
      targetPrefix = (i * stepSize).uint16
      targetByte1 = (targetPrefix shr 8).byte
      targetByte2 = (targetPrefix and 0xFF).byte

    while true:
      let
        privKey = PrivateKey.random(rng)
        pubKey = privKey.toPublicKey.toRaw()
        nodeIdBytes = keccak256(pubKey).data

      if nodeIdBytes[0] == targetByte1 and nodeIdBytes[1] == targetByte2:
        res[i] = privKey
        break

  res

proc discover(
    d: discv5_protocol.Protocol, psFile: string
) {.async: (raises: [CancelledError]).} =
  info "Starting node discovery - storing nodes at: ", psFile

  var seenNodes = initHashSet[NodeId]()

  let f =
    try:
      open(psFile, fmWrite)
    except IOError as e:
      fatal "Failed to open file for writing", file = psFile, error = e.msg
      quit QuitFailure

  defer:
    f.close()

  try:
    f.writeLine(
      "node_id,seq_number,ip:port,eth2,fork_digest,attnets,attnets_number,syncnets,eth,fork_hash,ENR,pubkey"
    )
  except IOError as e:
    fatal "Failed to write to file", file = psFile, error = e.msg
    quit QuitFailure

  while true:
    let t0 = now(chronos.Moment)
    let discovered = await d.queryRandom()
    let duration = now(chronos.Moment) - t0

    var newNodes = 0
    for n in discovered:
      if n.id in seenNodes:
        continue

      newNodes.inc()

      let
        # Known ENR fields used by Ethereum CL
        eth2Field = n.record.tryGet("eth2", seq[byte])
        attnetsField = n.record.tryGet("attnets", seq[byte])
        syncnetsField = n.record.tryGet("syncnets", seq[byte])
        # Known ENR fields used by Ethereum EL
        ethField = n.record.tryGet("eth", seq[byte])
        # There are more for the other rlpx protocols such as "snap"

        eth2 =
          if eth2Field.isSome:
            eth2Field.get().to0xHex()
          else:
            ""
        attnets =
          if attnetsField.isSome:
            attnetsField.get().to0xHex()
          else:
            ""
        syncnets =
          if syncnetsField.isSome:
            syncnetsField.get().to0xHex()
          else:
            ""
        eth =
          if ethField.isSome:
            ethField.get().to0xHex()
          else:
            ""

        forkDigest =
          if eth2Field.isSome:
            eth2Field.value()[0 .. 3].to0xHex()
          else:
            ""

        attnetsAmount =
          if attnetsField.isSome:
            var bits = 0
            for b in attnetsField.value():
              bits.inc(countOnes(b.uint8))
            $bits
          else:
            ""

        forkHash =
          if ethField.isSome:
            var rlp = rlpFromBytes(ethField.value())
            # It's a double RLP list, see
            # https://github.com/ethereum/devp2p/blob/bc76b9809a30e6dc5c8dcda996273f0f9bcf7108/enr-entries/eth.md#entry-format
            if rlp.enterList and rlp.enterList:
              try:
                rlp.read(seq[byte]).to0xHex()
              except RlpError:
                "Invalid fork hash"
            else:
              "Invalid fork hash"
          else:
            ""

      try:
        f.writeLine(
          [
            n.id.toHex,
            $n.record.seqNum,
            $n.address.value(),
            eth2,
            forkDigest,
            attnets,
            attnetsAmount,
            syncnets,
            eth,
            forkHash,
            n.record.toURI(),
            $n.record.publicKey,
          ].join(",")
        )
      except IOError as e:
        fatal "Failed to write to file", file = psFile, error = e.msg
        quit QuitFailure

      seenNodes.incl(n.id)

    info "Node random lookup finished",
      query_time_ms = duration.millis, discovered_nodes = discovered.len, new_nodes = newNodes, total_nodes = len(seenNodes)

    await sleepAsync(100.milliseconds) # 100 ms of idle time

proc setupNode(config: DiscoveryConf): discv5_protocol.Protocol {.raises: [CatchableError].} =
  let
    bindIp = config.listenAddress
    udpPort = Port(config.udpPort)
    # TODO: allow for no TCP port mapping!
    (extIp, _, extUdpPort) = setupAddress(config.nat,
      config.listenAddress, udpPort, udpPort, "dcli")

  let d = newProtocol(config.nodeKey,
          extIp, Opt.none(Port), extUdpPort,
          bootstrapRecords = config.bootstrapNodes,
          bindIp = bindIp, bindPort = udpPort,
          enrAutoUpdate = config.enrAutoUpdate)
  d.open()

  if config.metricsEnabled:
    let
      address = config.metricsAddress
      port = config.metricsPort
      url = "http://" & $address & ":" & $port & "/metrics"
      server = MetricsHttpServerRef.new($address, port).valueOr:
        error "Could not instantiate metrics HTTP server", url, error
        quit QuitFailure

    info "Starting metrics HTTP server", url
    try:
      waitFor server.start()
    except MetricsError as exc:
      fatal "Could not start metrics HTTP server",
        url, error_msg = exc.msg, error_name = exc.name
      quit QuitFailure

  d

proc run(config: DiscoveryConf) {.raises: [CatchableError].} =
  case config.cmd
  of ping:
    let d = setupNode(config)
    let pong = waitFor d.ping(config.pingTarget)
    if pong.isOk():
      echo pong[]
    else:
      echo "No Pong message returned"
  of findNode:
    let d = setupNode(config)
    let nodes = waitFor d.findNode(config.findNodeTarget, @[config.distance])
    if nodes.isOk():
      echo "Received valid records:"
      for node in nodes[]:
        echo $node.record & " - " & shortLog(node)
    else:
      echo "No Nodes message returned"
  of talkReq:
    let d = setupNode(config)
    let talkresp = waitFor d.talkReq(config.talkReqTarget, @[], @[])
    if talkresp.isOk():
      echo talkresp[]
    else:
      echo "No Talk Response message returned"
  of noCommand:
    let d = setupNode(config)
    d.start()
    waitFor(discover(d, config.persistingFile))
  of generateKeys:
    let keys = generateDistributedNetKeys(keys.newRng()[], uint16(config.numKeys))

    echo "Generated ", keys.len, " evenly distributed keys:"
    echo ""
    for i, key in keys:
      let
        pubKey = key.toPublicKey.toRaw()
        nodeId = keccak256(pubKey)
        nodeIdHex = nodeId.toHex()

      echo "Key ", i + 1, ":"
      echo "Private Key: ", $key
      echo "Node ID: ", nodeIdHex
      echo "First 2 Bytes: 0x", nodeIdHex[0..3]
      echo ""

when isMainModule:
  {.pop.}
  let config = DiscoveryConf.load()
  {.push raises: [].}

  setLogLevel(config.logLevel)

  run(config)
