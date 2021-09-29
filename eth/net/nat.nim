# Copyright (c) 2019-2021 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  std/[options, os, strutils, times],
  stew/results, nat_traversal/[miniupnpc, natpmp],
  chronicles, json_serialization/std/net, chronos,
  ../common/utils, ./utils as netutils

type
  NatStrategy* = enum
    NatAny
    NatUpnp
    NatPmp
    NatNone

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
  topics = "nat"

## Also does threadvar initialisation.
## Must be called before redirectPorts() in each thread.
proc getExternalIP*(natStrategy: NatStrategy, quiet = false): Option[IpAddress] =
  var externalIP: IPAddress

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
            return some(externalIP)
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
          return some(externalIP)
        except ValueError as e:
          error "parseIpAddress() exception", err = e.msg
          return

proc doPortMapping(tcpPort, udpPort: Port, description: string): Option[(Port, Port)] {.gcsafe.} =
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
  return some((extTcpPort, extUdpPort))

type PortMappingArgs = tuple[tcpPort, udpPort: Port, description: string]
var
  natThread: Thread[PortMappingArgs]
  natCloseChan: Channel[bool]

proc repeatPortMapping(args: PortMappingArgs) {.thread.} =
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
      let (dataAvailable, _) = natCloseChan.tryRecv()
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

  natCloseChan.send(true)
  natThread.joinThread()
  natCloseChan.close()

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

proc redirectPorts*(tcpPort, udpPort: Port, description: string): Option[(Port, Port)] =
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
    natThread.createThread(repeatPortMapping, (externalTcpPort, externalUdpPort, description))
    # atexit() in disguise
    addQuitProc(stopNatThread)

proc setupNat*(natStrategy: NatStrategy, tcpPort, udpPort: Port,
    clientId: string):
    tuple[ip: Option[ValidIpAddress], tcpPort, udpPort: Option[Port]] =
  ## Setup NAT port mapping and get external IP address.
  ## If any of this fails, we don't return any IP address but do return the
  ## original ports as best effort.
  ## TODO: Allow for tcp or udp port mapping to be optional.
  let extIp = getExternalIP(natStrategy)
  if extIP.isSome:
    let ip = ValidIpAddress.init(extIp.get)
    let extPorts = ({.gcsafe.}:
      redirectPorts(tcpPort = tcpPort,
                    udpPort = udpPort,
                    description = clientId))
    if extPorts.isSome:
      let (extTcpPort, extUdpPort) = extPorts.get()
      (ip: some(ip), tcpPort: some(extTcpPort), udpPort: some(extUdpPort))
    else:
      warn "UPnP/NAT-PMP available but port forwarding failed"
      (ip: none(ValidIpAddress), tcpPort: some(tcpPort), udpPort: some(udpPort))
  else:
    warn "UPnP/NAT-PMP not available"
    (ip: none(ValidIpAddress), tcpPort: some(tcpPort), udpPort: some(udpPort))

type
  NatConfig* = object
    case hasExtIp*: bool
      of true: extIp*: ValidIpAddress
      of false: nat*: NatStrategy

func parseCmdArg*(T: type NatConfig, p: TaintedString): T =
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
          let ip = ValidIpAddress.init(p[6..^1])
          NatConfig(hasExtIp: true, extIp: ip)
        except ValueError:
          let error = "Not a valid IP address: " & p[6..^1]
          raise newException(ConfigurationError, error)
      else:
        let error = "Not a valid NAT option: " & p
        raise newException(ConfigurationError, error)

func completeCmdArg*(T: type NatConfig, val: TaintedString): seq[string] =
  return @[]

proc setupAddress*(natConfig: NatConfig, bindIp: ValidIpAddress,
    tcpPort, udpPort: Port, clientId: string):
    tuple[ip: Option[ValidIpAddress], tcpPort, udpPort: Option[Port]]
    {.gcsafe.} =
  ## Set-up of the external address via any of the ways as configured in
  ## `NatConfig`. In case all fails an error is logged and the bind ports are
  ## selected also as external ports, as best effort and in hope that the
  ## external IP can be figured out by other means at a later stage.
  ## TODO: Allow for tcp or udp bind ports to be optional.

  if natConfig.hasExtIp:
    # any required port redirection must be done by hand
    return (some(natConfig.extIp), some(tcpPort), some(udpPort))

  case natConfig.nat:
    of NatAny:
      let bindAddress = initTAddress(bindIP, Port(0))
      if bindAddress.isAnyLocal():
        let ip = getRouteIpv4()
        if ip.isErr():
          # No route was found, log error and continue without IP.
          error "No routable IP address found, check your network connection",
            error = ip.error
          return (none(ValidIpAddress), some(tcpPort), some(udpPort))
        elif ip.get().isPublic():
          return (some(ip.get()), some(tcpPort), some(udpPort))
        else:
          # Best route IP is not public, might be an internal network and the
          # node is either behind a gateway with NAT or for example a container
          # or VM bridge (or both). Lets try UPnP and NAT-PMP for the case where
          # the node is behind a gateway with UPnP or NAT-PMP support.
          return setupNat(natConfig.nat, tcpPort, udpPort, clientId)
      elif bindAddress.isPublic():
        # When a specific public interface is provided, use that one.
        return (some(ValidIpAddress.init(bindIP)), some(tcpPort), some(udpPort))
      else:
        return setupNat(natConfig.nat, tcpPort, udpPort, clientId)
    of NatNone:
      let bindAddress = initTAddress(bindIP, Port(0))
      if bindAddress.isAnyLocal():
        let ip = getRouteIpv4()
        if ip.isErr():
          # No route was found, log error and continue without IP.
          error "No routable IP address found, check your network connection",
            error = ip.error
          return (none(ValidIpAddress), some(tcpPort), some(udpPort))
        elif ip.get().isPublic():
          return (some(ip.get()), some(tcpPort), some(udpPort))
        else:
          error "No public IP address found. Should not use --nat:none option"
          return (none(ValidIpAddress), some(tcpPort), some(udpPort))
      elif bindAddress.isPublic():
        # When a specific public interface is provided, use that one.
        return (some(ValidIpAddress.init(bindIP)), some(tcpPort), some(udpPort))
      else:
        error "Bind IP is not a public IP address. Should not use --nat:none option"
        return (none(ValidIpAddress), some(tcpPort), some(udpPort))
    of NatUpnp, NatPmp:
      return setupNat(natConfig.nat, tcpPort, udpPort, clientId)
