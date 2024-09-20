# Copyright (c) 2019-2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

{.push raises: [].}

import
  std/[os, strutils, times],
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

const
  UPNP_TIMEOUT = 200 # ms
  PORT_MAPPING_INTERVAL = 20 * 60 # seconds
  NATPMP_LIFETIME = 60 * 60 # in seconds, must be longer than PORT_MAPPING_INTERVAL

var
  upnp {.threadvar.}: Miniupnp
  npmp {.threadvar.}: NatPmp
  strategy = NatNone
  internalTcpPort: Port
  externalTcpPort: Port
  internalUdpPort: Port
  externalUdpPort: Port

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

proc doPortMapping(tcpPort, udpPort: Port, description: string): Opt[(Port, Port)] {.gcsafe.} =
  var
    extTcpPort: Port
    extUdpPort: Port

  if strategy == NatUpnp:
    for t in [(tcpPort, UPNPProtocol.TCP), (udpPort, UPNPProtocol.UDP)]:
      let
        (port, protocol) = t
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
        case protocol:
          of UPNPProtocol.TCP:
            extTcpPort = port
          of UPNPProtocol.UDP:
            extUdpPort = port
  elif strategy == NatPmp:
    for t in [(tcpPort, NatPmpProtocol.TCP), (udpPort, NatPmpProtocol.UDP)]:
      let
        (port, protocol) = t
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
        case protocol:
          of NatPmpProtocol.TCP:
            extTcpPort = extPort
          of NatPmpProtocol.UDP:
            extUdpPort = extPort
  return Opt.some((extTcpPort, extUdpPort))

type PortMappingArgs = tuple[tcpPort, udpPort: Port, description: string]
var
  natThread: Thread[PortMappingArgs]
  natCloseChan: Channel[bool]

proc repeatPortMapping(args: PortMappingArgs) {.thread, raises: [ValueError].} =
  ignoreSignalsInThread()
  let
    (tcpPort, udpPort, description) = args
    interval = initDuration(seconds = PORT_MAPPING_INTERVAL)
    sleepDuration = 1_000 # in ms, also the maximum delay after pressing Ctrl-C

  var lastUpdate = now()

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
          discard doPortMapping(tcpPort, udpPort, description)
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
      for t in [(externalTcpPort, internalTcpPort, UPNPProtocol.TCP), (externalUdpPort, internalUdpPort, UPNPProtocol.UDP)]:
        let
          (eport, iport, protocol) = t
          pmres = upnp.deletePortMapping(externalPort = $eport,
                                          protocol = protocol)
        if pmres.isErr:
          error "UPnP port mapping deletion", msg = pmres.error
        else:
          debug "UPnP: deleted port mapping", externalPort = eport, internalPort = iport, protocol = protocol
    elif strategy == NatPmp:
      for t in [(externalTcpPort, internalTcpPort, NatPmpProtocol.TCP), (externalUdpPort, internalUdpPort, NatPmpProtocol.UDP)]:
        let
          (eport, iport, protocol) = t
          pmres = npmp.deletePortMapping(eport = eport.cushort,
                                          iport = iport.cushort,
                                          protocol = protocol)
        if pmres.isErr:
          error "NAT-PMP port mapping deletion", msg = pmres.error
        else:
          debug "NAT-PMP: deleted port mapping", externalPort = eport, internalPort = iport, protocol = protocol

proc redirectPorts*(tcpPort, udpPort: Port, description: string): Opt[(Port, Port)] =
  result = doPortMapping(tcpPort, udpPort, description)
  if result.isSome:
    (externalTcpPort, externalUdpPort) = result.get()
    # needed by NAT-PMP on port mapping deletion
    internalTcpPort = tcpPort
    internalUdpPort = udpPort
    # Port mapping works. Let's launch a thread that repeats it, in case the
    # NAT-PMP lease expires or the router is rebooted and forgets all about
    # these mappings.
    natCloseChan.open()
    try:
      natThread.createThread(repeatPortMapping, (externalTcpPort, externalUdpPort, description))
      # atexit() in disguise
      addQuitProc(stopNatThread)
    except Exception as exc:
      warn "Failed to create NAT port mapping renewal thread", exc = exc.msg

proc setupNat*(natStrategy: NatStrategy, tcpPort, udpPort: Port,
    clientId: string):
    tuple[ip: Opt[IpAddress], tcpPort, udpPort: Opt[Port]] =
  ## Setup NAT port mapping and get external IP address.
  ## If any of this fails, we don't return any IP address but do return the
  ## original ports as best effort.
  ## TODO: Allow for tcp or udp port mapping to be optional.
  let extIp = getExternalIP(natStrategy)
  if extIp.isSome:
    let ip = extIp.get
    let extPorts = ({.gcsafe.}:
      redirectPorts(tcpPort = tcpPort,
                    udpPort = udpPort,
                    description = clientId))
    if extPorts.isSome:
      let (extTcpPort, extUdpPort) = extPorts.get()
      (ip: Opt.some(ip), tcpPort: Opt.some(extTcpPort), udpPort: Opt.some(extUdpPort))
    else:
      warn "UPnP/NAT-PMP available but port forwarding failed"
      (ip: Opt.none(IpAddress), tcpPort: Opt.some(tcpPort), udpPort: Opt.some(udpPort))
  else:
    warn "UPnP/NAT-PMP not available"
    (ip: Opt.none(IpAddress), tcpPort: Opt.some(tcpPort), udpPort: Opt.some(udpPort))

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

proc setupAddress*(natConfig: NatConfig, bindIp: IpAddress,
    tcpPort, udpPort: Port, clientId: string):
    tuple[ip: Opt[IpAddress], tcpPort, udpPort: Opt[Port]]
    {.gcsafe.} =
  ## Set-up of the external address via any of the ways as configured in
  ## `NatConfig`. In case all fails an error is logged and the bind ports are
  ## selected also as external ports, as best effort and in hope that the
  ## external IP can be figured out by other means at a later stage.
  ## TODO: Allow for tcp or udp bind ports to be optional.

  if natConfig.hasExtIp:
    # any required port redirection must be done by hand
    return (Opt.some(natConfig.extIp), Opt.some(tcpPort), Opt.some(udpPort))

  case natConfig.nat:
    of NatAny:
      let (prefSrcIp, prefSrcStatus) = getRoutePrefSrc(bindIp)

      case prefSrcStatus:
        of NoRoutingInfo, PrefSrcIsPublic, BindAddressIsPublic:
          return (prefSrcIp, Opt.some(tcpPort), Opt.some(udpPort))
        of PrefSrcIsPrivate, BindAddressIsPrivate:
          return setupNat(natConfig.nat, tcpPort, udpPort, clientId)
    of NatNone:
      let (prefSrcIp, prefSrcStatus) = getRoutePrefSrc(bindIp)

      case prefSrcStatus:
        of NoRoutingInfo, PrefSrcIsPublic, BindAddressIsPublic:
          return (prefSrcIp, Opt.some(tcpPort), Opt.some(udpPort))
        of PrefSrcIsPrivate:
          error "No public IP address found. Should not use --nat:none option"
          return (Opt.none(IpAddress), Opt.some(tcpPort), Opt.some(udpPort))
        of BindAddressIsPrivate:
          error "Bind IP is not a public IP address. Should not use --nat:none option"
          return (Opt.none(IpAddress), Opt.some(tcpPort), Opt.some(udpPort))
    of NatUpnp, NatPmp:
      return setupNat(natConfig.nat, tcpPort, udpPort, clientId)
