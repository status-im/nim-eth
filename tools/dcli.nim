# Copyright (c) 2020-2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

{.push raises: [].}

import
  std/[options, strutils, tables, sets],
  confutils, confutils/std/net, chronicles, chronicles/topics_registry,
  chronos, metrics, metrics/chronos_httpserver, stew/byteutils, stew/bitops2,
  ./eth/keys, ./eth/net/nat,
  ./eth/p2p/discoveryv5/[enr, node],
  ./eth/p2p/discoveryv5/protocol as discv5_protocol

type
  DiscoveryCmd* = enum
    noCommand
    ping
    findNode
    talkReq

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
      defaultValue: defaultListenAddress(config)
      desc: "Listening address for the Discovery v5 traffic"
      name: "listen-address" }: ValidIpAddress

    persistingFile* {.
      defaultValue: "peerstore.csv",
      desc: "File where the tool will keep the discovered records"
      name: "persisting-file" .}: string

    bootnodes* {.
      desc: "ENR URI of node to bootstrap discovery with. Argument may be repeated"
      name: "bootnode" .}: seq[enr.Record]

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
      defaultValue: defaultAdminListenAddress(config)
      desc: "Listening address of the metrics server"
      name: "metrics-address" .}: ValidIpAddress

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

func defaultListenAddress*(conf: DiscoveryConf): ValidIpAddress =
  (static ValidIpAddress.init("0.0.0.0"))

func defaultAdminListenAddress*(conf: DiscoveryConf): ValidIpAddress =
  (static ValidIpAddress.init("127.0.0.1"))

proc parseCmdArg*(T: type enr.Record, p: string): T {.raises: [ValueError].} =
  if not fromURI(result, p):
    raise newException(ValueError, "Invalid ENR")

proc completeCmdArg*(T: type enr.Record, val: string): seq[string] =
  return @[]

proc parseCmdArg*(T: type Node, p: string): T {.raises: [ValueError].} =
  var record: enr.Record
  if not fromURI(record, p):
    raise newException(ValueError, "Invalid ENR")

  let n = newNode(record)
  if n.isErr:
    raise newException(ValueError, $n.error)

  if n[].address.isNone():
    raise newException(ValueError, "ENR without address")

  n[]

proc completeCmdArg*(T: type Node, val: string): seq[string] =
  return @[]

proc parseCmdArg*(T: type PrivateKey, p: string): T {.raises: [ValueError].} =
  try:
    result = PrivateKey.fromHex(string(p)).tryGet()
  except CatchableError:
    raise newException(ValueError, "Invalid private key")

proc completeCmdArg*(T: type PrivateKey, val: string): seq[string] =
  return @[]

proc discover(d: discv5_protocol.Protocol, psFile: string) {.async.} =
  info "Starting peer-discovery in Ethereum - persisting peers at: ", psFile

  var ethNodes: HashSet[seq[byte]]

  let ps = open(psFile, fmWrite)
  defer: ps.close()
  ps.write("pubkey,node_id,fork_digest,ip:port,attnets,attnets_number\n")

  while true:
    let iTime = now(chronos.Moment)
    let discovered = await d.queryRandom()
    let qDuration = now(chronos.Moment) - iTime
    info "Lookup finished",  query_time = qDuration.secs, new_nodes = discovered.len, tot_peers=len(ethNodes)

    for dNode in discovered:
      let eth2 = dNode.record.tryGet("eth2", seq[byte])
      let pubkey = dNode.record.tryGet("secp256k1", seq[byte])
      let attnets = dNode.record.tryGet("attnets", seq[byte])
      if eth2.isNone or attnets.isNone or pubkey.isNone: continue

      if pubkey.get() in ethNodes: continue
      ethNodes.incl(pubkey.get())

      let forkDigest = eth2.get()

      var bits = 0
      for byt in attnets.get():
        bits.inc(countOnes(byt.uint))

      let str = "$#,$#,$#,$#,$#,$#\n"
      let newLine = str % [pubkey.get().toHex, dNode.id.toHex, forkDigest[0..3].toHex, $dNode.address.get(), attnets.get().toHex, $bits]

      ps.write(newLine)
    await sleepAsync(1000) # 1 sec of delay


proc run(config: DiscoveryConf) {.raises: [CatchableError].} =
  let
    bindIp = config.listenAddress
    udpPort = Port(config.udpPort)
    # TODO: allow for no TCP port mapping!
    (extIp, _, extUdpPort) = setupAddress(config.nat,
      config.listenAddress, udpPort, udpPort, "dcli")

  let d = newProtocol(config.nodeKey,
          extIp, none(Port), extUdpPort,
          bootstrapRecords = config.bootnodes,
          bindIp = bindIp, bindPort = udpPort,
          enrAutoUpdate = config.enrAutoUpdate)

  d.open()

  if config.metricsEnabled:
    let
      address = config.metricsAddress
      port = config.metricsPort
    notice "Starting metrics HTTP server",
      url = "http://" & $address & ":" & $port & "/metrics"
    try:
      chronos_httpserver.startMetricsHttpServer($address, port)
    except CatchableError as exc: raise exc
    except Exception as exc: raiseAssert exc.msg # TODO fix metrics

  case config.cmd
  of ping:
    let pong = waitFor d.ping(config.pingTarget)
    if pong.isOk():
      echo pong[]
    else:
      echo "No Pong message returned"
  of findNode:
    let nodes = waitFor d.findNode(config.findNodeTarget, @[config.distance])
    if nodes.isOk():
      echo "Received valid records:"
      for node in nodes[]:
        echo $node.record & " - " & shortLog(node)
    else:
      echo "No Nodes message returned"
  of talkReq:
    let talkresp = waitFor d.talkReq(config.talkReqTarget, @[], @[])
    if talkresp.isOk():
      echo talkresp[]
    else:
      echo "No Talk Response message returned"
  of noCommand:
    d.start()
    waitFor(discover(d, config.persistingFile))

when isMainModule:
  {.pop.}
  let config = DiscoveryConf.load()
  {.push raises: [].}

  setLogLevel(config.logLevel)

  run(config)
