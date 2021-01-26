import
  std/[options, strutils],
  chronos, chronicles, chronicles/topics_registry, confutils, metrics,
  stew/byteutils, confutils/std/net,
  eth/keys, eth/net/nat, enr, node, protocol

type
  DiscoveryCmd* = enum
    noCommand
    ping
    findnode
    talkreq

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

    bootnodes* {.
      desc: "ENR URI of node to bootstrap discovery with. Argument may be repeated"
      name: "bootnode" .}: seq[enr.Record]

    nat* {.
      desc: "Specify method to use for determining public address. " &
            "Must be one of: any, none, upnp, pmp, extip:<IP>"
      defaultValue: "any" .}: string

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
    of talkreq:
      talkreqTarget* {.
        argument
        desc: "ENR URI of the node to send a talkreq message"
        name: "node" .}: Node

func defaultListenAddress*(conf: DiscoveryConf): ValidIpAddress =
  (static ValidIpAddress.init("0.0.0.0"))

func defaultAdminListenAddress*(conf: DiscoveryConf): ValidIpAddress =
  (static ValidIpAddress.init("127.0.0.1"))

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

proc parseCmdArg*(T: type PrivateKey, p: TaintedString): T =
  try:
    result = PrivateKey.fromHex(string(p)).tryGet()
  except CatchableError as e:
    raise newException(ConfigurationError, "Invalid private key")

proc completeCmdArg*(T: type PrivateKey, val: TaintedString): seq[string] =
  return @[]

proc setupNat(conf: DiscoveryConf): tuple[ip: Option[ValidIpAddress],
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
        result.ip = some(ValidIpAddress.init(conf.nat[6..^1]))
        nat = NatNone
      else:
        error "not a valid NAT mechanism, nor a valid IP address", value = conf.nat
        quit(QuitFailure)

  if nat != NatNone:
    let extIp = getExternalIP(nat)
    if extIP.isSome:
      result.ip = some(ValidIpAddress.init extIp.get)
      let extPorts = ({.gcsafe.}:
        redirectPorts(tcpPort = result.tcpPort,
                      udpPort = result.udpPort,
                      description = "Discovery v5 ports"))
      if extPorts.isSome:
        (result.tcpPort, result.udpPort) = extPorts.get()

proc run(config: DiscoveryConf) =
  let
    (ip, tcpPort, udpPort) = setupNat(config)
    d = newProtocol(config.nodeKey, ip, tcpPort, udpPort,
      bootstrapRecords = config.bootnodes, bindIp = config.listenAddress,
      enrAutoUpdate = config.enrAutoUpdate)

  d.open()

  when defined(insecure):
    if config.metricsEnabled:
      let
        address = config.metricsAddress
        port = config.metricsPort
      info "Starting metrics HTTP server", address, port
      metrics.startHttpServer($address, port)

  case config.cmd
  of ping:
    let pong = waitFor d.ping(config.pingTarget)
    if pong.isOk():
      echo pong[]
    else:
      echo "No Pong message returned"
  of findnode:
    let nodes = waitFor d.findNode(config.findNodeTarget, @[config.distance])
    if nodes.isOk():
      echo "Received valid records:"
      for node in nodes[]:
        echo $node.record & " - " & shortLog(node)
    else:
      echo "No Nodes message returned"
  of talkreq:
    let talkresp = waitFor d.talkreq(config.talkreqTarget, @[], @[])
    if talkresp.isOk():
      echo talkresp[]
    else:
      echo "No Talk Response message returned"
  of noCommand:
    d.start()
    runForever()

when isMainModule:
  let config = DiscoveryConf.load()

  if config.logLevel != LogLevel.NONE:
    setLogLevel(config.logLevel)

  run(config)
