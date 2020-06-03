import
  sequtils, options, strutils, chronos, chronicles, chronicles/topics_registry,
  stew/byteutils, confutils,
  eth/keys, eth/trie/db, eth/net/nat,
  eth/p2p/discoveryv5/[protocol, discovery_db, enr, node]

type
  DiscoveryCmd* = enum
    noCommand
    ping
    findnode

  DiscoveryConf* = object
    logLevel* {.
      defaultValue: LogLevel.DEBUG
      desc: "Sets the log level."
      name: "log-level" .}: LogLevel

    udpPort* {.
      defaultValue: 9009
      desc: "UDP listening port."
      name: "udp-port" .}: uint16

    bootnodes* {.
      desc: "ENR URI of node to bootstrap discovery with. Argument may be repeated."
      name: "bootnode" .}: seq[enr.Record]

    nat* {.
      desc: "Specify method to use for determining public address. " &
            "Must be one of: any, none, upnp, pmp, extip:<IP>."
      defaultValue: "any" .}: string

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
    of findnode:
      distance* {.
        defaultValue: 255
        desc: "Distance parameter for the findNode message"
        name: "distance" .}: uint32
      # TODO: Order here matters as else the help message does not show all the
      # information, see: https://github.com/status-im/nim-confutils/issues/15
      findNodeTarget* {.
        argument
        desc: "ENR URI of the node to send a findNode message"
        name: "node" .}: Node

proc parseCmdArg*(T: type enr.Record, p: TaintedString): T =
  if not fromURI(result, p):
    raise newException(ConfigurationError, "Invalid ENR")

proc completeCmdArg*(T: type enr.Record, val: TaintedString): seq[string] =
  return @[]

proc parseCmdArg*(T: type Node, p: TaintedString): T =
  var record: enr.Record
  if not fromURI(record, p):
    raise newException(ConfigurationError, "Invalid ENR")

  let n = newNode(record)
  if n.isErr:
    raise newException(ConfigurationError, $n.error)

  if n[].address.isNone():
    raise newException(ConfigurationError, "ENR without address")

  n[]

proc completeCmdArg*(T: type Node, val: TaintedString): seq[string] =
  return @[]

proc setupNat(conf: DiscoveryConf): tuple[ip: Option[IpAddress],
                                          tcpPort: Port,
                                          udpPort: Port] {.gcsafe.} =
  # defaults
  result.tcpPort = Port(conf.udpPort)
  result.udpPort = Port(conf.udpPort)

  var nat: NatStrategy
  case conf.nat.toLowerAscii:
    of "any":
      nat = NatAny
    of "none":
      nat = NatNone
    of "upnp":
      nat = NatUpnp
    of "pmp":
      nat = NatPmp
    else:
      if conf.nat.startsWith("extip:") and isIpAddress(conf.nat[6..^1]):
        # any required port redirection is assumed to be done by hand
        result.ip = some(parseIpAddress(conf.nat[6..^1]))
        nat = NatNone
      else:
        error "not a valid NAT mechanism, nor a valid IP address", value = conf.nat
        quit(QuitFailure)

  if nat != NatNone:
    result.ip = getExternalIP(nat)
    if result.ip.isSome:
      let extPorts = ({.gcsafe.}:
        redirectPorts(tcpPort = result.tcpPort,
                      udpPort = result.udpPort,
                      description = "Discovery v5 ports"))
      if extPorts.isSome:
        (result.tcpPort, result.udpPort) = extPorts.get()

proc run(config: DiscoveryConf) =
  let
    (ip, tcpPort, udpPort) = setupNat(config)
    privKey = PrivateKey.random().expect("Properly intialized private key")
    ddb = DiscoveryDB.init(newMemoryDB())
    # TODO: newProtocol should allow for no tcpPort
    d = newProtocol(privKey, ddb, ip, tcpPort, udpPort,
      bootstrapRecords = config.bootnodes)

  d.open()

  case config.cmd
  of ping:
    let pong = waitFor d.ping(config.pingTarget)
    if pong.isOk():
      echo pong[]
    else:
      echo "No Pong message returned"
  of findnode:
    let nodes = waitFor d.findNode(config.findNodeTarget, config.distance)
    if nodes.isOk():
      echo "Received valid records:"
      for node in nodes[]:
        echo $node.record & " - " & $node
    else:
      echo "No Nodes message returned"
  of noCommand:
    d.start()
    runForever()

when isMainModule:
  let config = DiscoveryConf.load()

  if config.logLevel != LogLevel.NONE:
    setLogLevel(config.logLevel)

  run(config)
