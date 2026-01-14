# Copyright (c) 2019-2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

{.push raises: [].}

import
  std/[os, sequtils, strutils, times, tables],
  results, nat_traversal/[miniupnpc, natpmp],
  chronicles, json_serialization/std/net, chronos,
  ./utils as netutils

export results

type
  NatStrategy* = enum
    NatAny
    NatUpnp
    NatPmp
    NatNone

  PrefSrcStatus = enum
    NoRoutingInfo
    PrefSrcIsPublic
    PrefSrcIsPrivate
    BindAddressIsPublic
    BindAddressIsPrivate

  PortProtocol* {.pure.} = enum
    UDP
    TCP

  PortSpec* = tuple[port: Port, protocol: PortProtocol]

const
  UPNP_TIMEOUT = 200 # ms
  PORT_MAPPING_INTERVAL = 20 * 60 # seconds
  NATPMP_LIFETIME = 60 * 60 # in seconds, must be longer than PORT_MAPPING_INTERVAL

var
  upnp {.threadvar.}: Miniupnp
  npmp {.threadvar.}: NatPmp
  strategy = NatNone
  portMapping = initTable[PortSpec, PortSpec]()

logScope:
  topics = "eth net nat"

when defined(posix):
  import std/posix

# Block all/most signals in the current thread, so we don't interfere with regular signal
# handling elsewhere.
proc ignoreSignalsInThread() =
  when defined(posix):
    var signalMask, oldSignalMask: Sigset

    # sigprocmask() doesn't work on macOS, for multithreaded programs
    if sigfillset(signalMask) != 0:
      echo osErrorMsg(osLastError())
      quit(QuitFailure)
    if pthread_sigmask(SIG_BLOCK, signalMask, oldSignalMask) != 0:
      echo osErrorMsg(osLastError())
      quit(QuitFailure)

## Also does threadvar initialisation.
## Must be called before redirectPorts() in each thread.
proc getExternalIP*(natStrategy: NatStrategy, quiet = false): Opt[IpAddress] =
  var externalIP: IpAddress

  if natStrategy == NatAny or natStrategy == NatUpnp:
    if upnp == nil:
      upnp = newMiniupnp()

    upnp.discoverDelay = UPNP_TIMEOUT
    let dres = upnp.discover()
    if dres.isErr:
      debug "UPnP", msg = dres.error
    else:
      var
        msg: cstring
        canContinue = true
      case upnp.selectIGD():
        of IGDNotFound:
          msg = "Internet Gateway Device not found. Giving up."
          canContinue = false
        of IGDFound:
          msg = "Internet Gateway Device found."
        of IGDIpNotRoutable:
          msg = "Internet Gateway Device found and is connected, but with a reserved or non-routable IP. Trying anyway."
        of IGDNotConnected:
          msg = "Internet Gateway Device found but it's not connected. Trying anyway."
        of NotAnIGD:
          msg = "Some device found, but it's not recognised as an Internet Gateway Device. Trying anyway."
      if not quiet:
        debug "UPnP", msg
      if canContinue:
        let ires = upnp.externalIPAddress()
        if ires.isErr:
          debug "UPnP", msg = ires.error
        else:
          # if we got this far, UPnP is working and we don't need to try NAT-PMP
          try:
            externalIP = parseIpAddress(ires.value)
            strategy = NatUpnp
            return Opt.some(externalIP)
          except ValueError as e:
            error "parseIpAddress() exception", err = e.msg
            return

  if natStrategy == NatAny or natStrategy == NatPmp:
    if npmp == nil:
      npmp = newNatPmp()
    let nres = npmp.init()
    if nres.isErr:
      debug "NAT-PMP", msg = nres.error
    else:
      let nires = npmp.externalIPAddress()
      if nires.isErr:
        debug "NAT-PMP", msg = nires.error
      else:
        try:
          externalIP = parseIpAddress($(nires.value))
          strategy = NatPmp
          return Opt.some(externalIP)
        except ValueError as e:
          error "parseIpAddress() exception", err = e.msg
          return

# This queries the routing table to get the "preferred source" attribute and
# checks if it's a public IP. If so, then it's our public IP.
#
# Further more, we check if the bind address (user provided, or a "0.0.0.0"
# default) is a public IP. That's a long shot, because code paths involving a
# user-provided bind address are not supposed to get here.
proc getRoutePrefSrc(bindIp: IpAddress): (Opt[IpAddress], PrefSrcStatus) =
  let bindAddress = initTAddress(bindIp, Port(0))

  if bindAddress.isAnyLocal():
    let ip = getRouteIpv4()
    if ip.isErr():
      # No route was found, log error and continue without IP.
      error "No routable IP address found, check your network connection",
        error = ip.error
      return (Opt.none(IpAddress), NoRoutingInfo)
    elif ip.get().isGlobalUnicast():
      return (Opt.some(ip.get()), PrefSrcIsPublic)
    else:
      return (Opt.none(IpAddress), PrefSrcIsPrivate)
  elif bindAddress.isGlobalUnicast():
    return (Opt.some(bindIp), BindAddressIsPublic)
  else:
    return (Opt.none(IpAddress), BindAddressIsPrivate)

# Try to detect a public IP assigned to this host, before trying NAT traversal.
proc getPublicRoutePrefSrcOrExternalIP*(
    natStrategy: NatStrategy, bindIp: IpAddress, quiet = true):
    Opt[IpAddress] =
  let (prefSrcIp, prefSrcStatus) = getRoutePrefSrc(bindIp)

  case prefSrcStatus:
    of NoRoutingInfo, PrefSrcIsPublic, BindAddressIsPublic:
      return prefSrcIp
    of PrefSrcIsPrivate, BindAddressIsPrivate:
      let extIp = getExternalIP(natStrategy, quiet)
      if extIp.isSome:
        return Opt.some(extIp.get)

proc doPortMapping(ports: seq[PortSpec], description: string): Opt[seq[PortSpec]] {.gcsafe.} =
  var ret = newSeq[PortSpec]()
  if strategy == NatUpnp:
    for p in ports:
      let
        port = p.port
        protocol = case p.protocol
          of PortProtocol.UDP: UPNPProtocol.UDP
          of PortProtocol.TCP: UPNPProtocol.TCP
        pmres = upnp.addPortMapping(externalPort = $port,
                                    protocol = protocol,
                                    internalHost = upnp.lanAddr,
                                    internalPort = $port,
                                    desc = description,
                                    leaseDuration = 0)
      if pmres.isErr:
        error "UPnP port mapping", msg = pmres.error, port
        return
      else:
        # let's check it
        let cres = upnp.getSpecificPortMapping(externalPort = $port,
                                                protocol = protocol)
        if cres.isErr:
          warn "UPnP port mapping check failed. Assuming the check itself is broken and the port mapping was done.", msg = cres.error

        info "UPnP: added port mapping", externalPort = port, internalPort = port, protocol = protocol
        ret.add(p)
  elif strategy == NatPmp:
    for p in ports:
      let
        port = p.port
        protocol = case p.protocol
          of PortProtocol.UDP: NatPmpProtocol.UDP
          of PortProtocol.TCP: NatPmpProtocol.TCP
        pmres = npmp.addPortMapping(eport = port.cushort,
                                    iport = port.cushort,
                                    protocol = protocol,
                                    lifetime = NATPMP_LIFETIME)
      if pmres.isErr:
        error "NAT-PMP port mapping", msg = pmres.error, port
        return
      else:
        let extPort = Port(pmres.value)
        info "NAT-PMP: added port mapping", externalPort = extPort, internalPort = port, protocol = protocol
        ret.add((port: extPort, protocol: p.protocol))
  return Opt.some(ret)

type
  PortMappingsArg = object
    portsLen: int
    portsPtr: ptr PortSpec
    descLen: int
    descPtr: ptr char

  PortMappingsArgPtr = ptr PortMappingsArg

var
  natThread: Thread[PortMappingsArgPtr]
  natCloseChan: Channel[bool]


proc freePortMappingsArgPtr(args: PortMappingsArgPtr) =
  if args == nil:
    return
  if args.portsPtr != nil:
    deallocShared(args.portsPtr)
  if args.descPtr != nil:
    deallocShared(args.descPtr)
  deallocShared(args)

proc allocPortMappingsArgPtr(
    ports: seq[PortSpec], description: string
): PortMappingsArgPtr =
  let args = cast[PortMappingsArgPtr](allocShared(sizeof(PortMappingsArg)))

  args.portsLen = ports.len
  if ports.len > 0:
    args.portsPtr = cast[ptr PortSpec](allocShared(sizeof(PortSpec) * ports.len))
    copyMem(args.portsPtr, unsafeAddr ports[0], sizeof(PortSpec) * ports.len)
  else:
    args.portsPtr = nil

  args.descLen = description.len
  if description.len > 0:
    args.descPtr = cast[ptr char](allocShared(description.len))
    copyMem(args.descPtr, unsafeAddr description[0], description.len)
  else:
    args.descPtr = nil

  args

proc repeatPortMapping(args: PortMappingsArgPtr) {.thread.} =
  ignoreSignalsInThread()
  let
    interval = initDuration(seconds = PORT_MAPPING_INTERVAL)
    sleepDuration = 1_000 # in ms, also the maximum delay after pressing Ctrl-C

  var lastUpdate = now()

  var ports = newSeq[PortSpec](args.portsLen)
  var description = newString(args.descLen)
  if args.portsLen > 0 and args.portsPtr != nil:
    copyMem(addr ports[0], args.portsPtr, sizeof(PortSpec) * args.portsLen)
  if args.descLen > 0 and args.descPtr != nil:
    copyMem(addr description[0], args.descPtr, args.descLen)

  freePortMappingsArgPtr(args)

  # We can't use copies of Miniupnp and NatPmp objects in this thread, because they share
  # C pointers with other instances that have already been garbage collected, so
  # we use threadvars instead and initialise them again with getExternalIP(),
  # even though we don't need the external IP's value.
  let ipres = getExternalIP(strategy, quiet = true)
  if ipres.isSome:
    while true:
      # we're being silly here with this channel polling because we can't
      # select on Nim channels like on Go ones
      let (dataAvailable, _) = try: natCloseChan.tryRecv()
        except Exception: (false, false)
      if dataAvailable:
        return
      else:
        let currTime = now()
        if currTime >= (lastUpdate + interval):
          discard doPortMapping(ports, description)
          lastUpdate = currTime
        sleep(sleepDuration)

proc stopNatThread() {.noconv.} =
  # stop the thread

  try:
    natCloseChan.send(true)
    natThread.joinThread()
    natCloseChan.close()
  except Exception as exc:
    warn "Failed to stop NAT port mapping renewal thread", exc = exc.msg

  # delete our port mappings

  # FIXME: if the initial port mapping failed because it already existed for the
  # required external port, we should not delete it. It might have been set up
  # by another program.

  # In Windows, a new thread is created for the signal handler, so we need to
  # initialise our threadvars again.
  let ipres = getExternalIP(strategy, quiet = true)
  if ipres.isSome:
    if strategy == NatUpnp:
      for internal, external in portMapping:
        let protocol = case external.protocol
          of PortProtocol.UDP:
            UPNPProtocol.UDP
          of PortProtocol.TCP:
            UPNPProtocol.TCP
        let pmres = upnp.deletePortMapping(externalPort = $external.port,
                                           protocol = protocol)
        if pmres.isErr:
          error "UPnP port mapping deletion", msg = pmres.error
        else:
          debug "UPnP: deleted port mapping", externalPort = external.port, internalPort = internal.port, protocol = protocol
    elif strategy == NatPmp:
      for internal, external in portMapping:
        let protocol = case external.protocol
          of PortProtocol.UDP:
            NatPmpProtocol.UDP
          of PortProtocol.TCP:
            NatPmpProtocol.TCP
        let pmres = npmp.deletePortMapping(eport = external.port.cushort,
                                           iport = internal.port.cushort,
                                           protocol = protocol)
        if pmres.isErr:
          error "NAT-PMP port mapping deletion", msg = pmres.error
        else:
          debug "NAT-PMP: deleted port mapping", externalPort = external.port, internalPort = internal.port, protocol = protocol
    portMapping.clear()

proc redirectPorts*(internalPorts: seq[PortSpec], description: string): Opt[seq[PortSpec]] =
  for p in internalPorts:
    if portMapping.hasKey(p):
      error "Port mapping already exists", port = p.port, protocol = p.protocol
      return Opt.none(seq[PortSpec])

  result = doPortMapping(internalPorts, description)
  if result.isSome:
    let externalPorts = result.get()
    for i in 0..<internalPorts.len:
      portMapping[internalPorts[i]] = externalPorts[i]
    # Port mapping works. Let's launch a thread that repeats it, in case the
    # NAT-PMP lease expires or the router is rebooted and forgets all about
    # these mappings.
    natCloseChan.open()
    var sharedArgs: PortMappingsArgPtr = nil
    try:
      sharedArgs = allocPortMappingsArgPtr(externalPorts, description)
      natThread.createThread(repeatPortMapping, sharedArgs)
      # the thread now owns sharedArgs from this point
      sharedArgs = nil
      # atexit() in disguise
      addQuitProc(stopNatThread)
    except Exception as exc:
      freePortMappingsArgPtr(sharedArgs)
      for p in internalPorts:
        portMapping.del(p)
      warn "Failed to create NAT port mapping renewal thread", exc = exc.msg

proc redirectPorts*(tcpPort, udpPort: Port, description: string): Opt[(Port, Port)] {.deprecated: "Please use redirectPorts with a sequence of PortSpec instead".} =
  let portsOpt = redirectPorts(@[(port: tcpPort, protocol: PortProtocol.TCP), (port: udpPort, protocol: PortProtocol.UDP)], description)
  if portsOpt.isSome:
    let ports = portsOpt.get()
    return Opt.some((ports[0].port, ports[1].port))

proc setupNat*(natStrategy: NatStrategy, ports: seq[PortSpec],
    clientId: string):
    tuple[ip: Opt[IpAddress], ports: seq[Opt[PortSpec]]] =
  ## Setup NAT port mapping and get external IP address.
  ## If any of this fails, we don't return any IP address but do return the
  ## original ports as best effort.
  let extIp =  getExternalIP(natStrategy).valueOr:
    warn "UPnP/NAT-PMP not available"
    return (ip: Opt.none(IpAddress), ports: ports.mapIt(Opt.some(it)))

  let extPorts = ({.gcsafe.}:
    redirectPorts(ports,
                  description = clientId)).valueOr:
    warn "UPnP/NAT-PMP available but port forwarding failed"
    return (ip: Opt.none(IpAddress), ports: ports.mapIt(Opt.some(it)))
  
  (ip: Opt.some(extIp), ports: extPorts.mapIt(Opt.some(it)))

proc setupNat*(natStrategy: NatStrategy, tcpPort, udpPort: Port,
    clientId: string):
    tuple[ip: Opt[IpAddress], tcpPort, udpPort: Opt[Port]] {.deprecated: "Please use setupNat with a sequence of PortSpec instead".} =
  let
    ports: seq[PortSpec] = @[(tcpPort, PortProtocol.TCP), (udpPort, PortProtocol.UDP)]
    setupNatRet = setupNat(natStrategy, ports, clientId)
    tcpPortRet =
      if setupNatRet.ports[0].isSome:
        Opt.some(setupNatRet.ports[0].get().port)
      else:
        Opt.none(Port)
    udpPortRet =
      if setupNatRet.ports[1].isSome:
        Opt.some(setupNatRet.ports[1].get().port)
      else:
        Opt.none(Port)
  (setupNatRet.ip, tcpPortRet, udpPortRet)

type
  NatConfig* = object
    case hasExtIp*: bool
      of true: extIp*: IpAddress
      of false: nat*: NatStrategy

func parseCmdArg*(T: type NatConfig, p: string): T {.raises: [ValueError].} =
  case p.toLowerAscii:
    of "any":
      NatConfig(hasExtIp: false, nat: NatAny)
    of "none":
      NatConfig(hasExtIp: false, nat: NatNone)
    of "upnp":
      NatConfig(hasExtIp: false, nat: NatUpnp)
    of "pmp":
      NatConfig(hasExtIp: false, nat: NatPmp)
    else:
      if p.startsWith("extip:"):
        try:
          let ip = parseIpAddress(p[6..^1])
          NatConfig(hasExtIp: true, extIp: ip)
        except ValueError:
          let error = "Not a valid IP address: " & p[6..^1]
          raise newException(ValueError, error)
      else:
        let error = "Not a valid NAT option: " & p
        raise newException(ValueError, error)

func completeCmdArg*(T: type NatConfig, val: string): seq[string] =
  return @[]

proc setupAddress*(natConfig: NatConfig, bindIp: IpAddress, ports: seq[PortSpec], clientId: string):
    tuple[ip: Opt[IpAddress], ports: seq[Opt[PortSpec]]]
    {.gcsafe.} =
  ## Set-up of the external address via any of the ways as configured in
  ## `NatConfig`. In case all fails an error is logged and the bind ports are
  ## selected also as external ports, as best effort and in hope that the
  ## external IP can be figured out by other means at a later stage.

  if natConfig.hasExtIp:
    # any required port redirection must be done by hand
    return (Opt.some(natConfig.extIp), ports.mapIt(Opt.some(it)))

  case natConfig.nat:
    of NatAny:
      let (prefSrcIp, prefSrcStatus) = getRoutePrefSrc(bindIp)

      case prefSrcStatus:
        of NoRoutingInfo, PrefSrcIsPublic, BindAddressIsPublic:
          return (prefSrcIp, ports.mapIt(Opt.some(it)))
        of PrefSrcIsPrivate, BindAddressIsPrivate:
          return setupNat(natConfig.nat, ports, clientId)
    of NatNone:
      let (prefSrcIp, prefSrcStatus) = getRoutePrefSrc(bindIp)

      case prefSrcStatus:
        of NoRoutingInfo, PrefSrcIsPublic, BindAddressIsPublic:
          return (prefSrcIp, ports.mapIt(Opt.some(it)))
        of PrefSrcIsPrivate:
          error "No public IP address found. Should not use --nat:none option"
          return (Opt.none(IpAddress), ports.mapIt(Opt.some(it)))
        of BindAddressIsPrivate:
          error "Bind IP is not a public IP address. Should not use --nat:none option"
          return (Opt.none(IpAddress), ports.mapIt(Opt.some(it)))
    of NatUpnp, NatPmp:
      return setupNat(natConfig.nat, ports, clientId)

proc setupAddress*(
    natConfig: NatConfig, bindIp: IpAddress, tcpPort, udpPort: Port, clientId: string
): tuple[ip: Opt[IpAddress], tcpPort, udpPort: Opt[Port]] {.
    gcsafe, deprecated: "Please use setupAddress with a sequence of PortSpec instead"
.} =
  let
    ports: seq[PortSpec] = @[(tcpPort, PortProtocol.TCP), (udpPort, PortProtocol.UDP)]
    setupAddressRet = setupAddress(natConfig, bindIp, ports, clientId)
    tcpPortRet =
      if setupAddressRet.ports[0].isSome:
        Opt.some(setupAddressRet.ports[0].get().port)
      else:
        Opt.none(Port)
    udpPortRet =
      if setupAddressRet.ports[1].isSome:
        Opt.some(setupAddressRet.ports[1].get().port)
      else:
        Opt.none(Port)
  (setupAddressRet.ip, tcpPortRet, udpPortRet)

func `==`*(a, b: NatConfig): bool =
  if a.hasExtIp != b.hasExtIp:
    return false

  case a.hasExtIp:
  of true: a.extIp == b.extIp
  of false: a.nat == b.nat

proc toPort*(p: PortSpec): Port =
  p.port

proc toPort*(p: Opt[PortSpec]): Opt[Port] =
  if p.isSome:
    Opt.some(p.get().port)
  else:
    Opt.none(Port)
