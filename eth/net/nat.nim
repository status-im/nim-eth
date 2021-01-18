# Copyright (c) 2019-2020 Status Research & Development GmbH
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
  eth/common/utils, ./utils as netutils

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
        error "UPnP port mapping", msg = pmres.error
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
        error "NAT-PMP port mapping", msg = pmres.error
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
    tuple[ip: Option[ValidIpAddress], tcpPort: Port, udpPort: Port] =
  # TODO: check and forward actual errors?

  let extIp = getExternalIP(natStrategy)
  if extIP.isSome:
    let ip = some(ValidIpAddress.init extIp.get)
    let extPorts = ({.gcsafe.}:
      redirectPorts(tcpPort = tcpPort,
                    udpPort = udpPort,
                    description = clientId))
    if extPorts.isSome:
      let (extTcpPort, extUdpPort) = extPorts.get()
      (ip, extTcpPort, extUdpPort)
    else:
      error "UPnP/NAT-PMP port forwarding failed"
      (none(ValidIpAddress), tcpPort, udpPort)
  else:
    error "UPnP/NAT-PMP failed"
    (none(ValidIpAddress), tcpPort, udpPort)

proc getBestRoutePublicIp*(): Option[ValidIpAddress] {.raises: [Defect].} =
  # Avoiding Exception with initTAddress and can't make it work with static.
  let publicAddress = TransportAddress(family: AddressFamily.IPv4,
    address_v4: [1'u8, 1, 1, 1], port: Port(0))
  # Note: `publicAddress` is only used an "example" IP to find the best route,
  # no data is send over the network to this IP!
  let route = getBestRoute(publicAddress)
  if (not route.source.isUnspecified()) and route.source.isPublic():
    let ip = try: route.source.address()
             except ValueError as e:
               error "Not a valid IP address", exception = e.name, msg = e.msg
               return none(ValidIpAddress)

    return some(ValidIpAddress.init(ip))

proc setupAddress*(nat: string, bindIP: ValidIpAddress, tcpPort, udpPort: Port,
    clientId: string):
    tuple[ip: Option[ValidIpAddress], tcpPort: Port, udpPort: Port] {.gcsafe.} =
  case nat.toLowerAscii:
    of "any":
      let bindAddress = initTAddress(bindIP, Port(0))
      if bindAddress.isAnyLocal() or not bindAddress.isSiteLocal():
        # Note: could also treat the bindAddress case different so that
        # we always use that address and never fail when it is a public IP.
        let ip = getBestRoutePublicIp()
        if ip.isSome():
          return (ip, tcpPort, udpPort)
        else:
          # Best route IP is private, thus this is an internal network and the
          # node is either behind a gateway with NAT or for example a container
          # or VM bridge (or both). Lets default try UPnP and NAT-PMP for in
          # the node is behind a gateway with UPnP or NAT-PMP support.
          return setupNat(NatAny, tcpPort, udpPort, clientId)
      else:
        return setupNat(NatAny, tcpPort, udpPort, clientId)
    of "none":
      let bindAddress = initTAddress(bindIP, Port(0))
      if bindAddress.isAnyLocal() or not bindAddress.isSiteLocal():
        # Note: could also treat the bindAddress case different so that
        # we always use that address and never fail when it is a public IP.
        let ip = getBestRoutePublicIp()
        if ip.isNone():
          warn "No public IP address found. Should not use --nat:none option"
        return (ip, tcpPort, udpPort)
      else:
        warn "Private IP address used as bind address. Should not use --nat:none option"
        return (none(ValidIpAddress), tcpPort, udpPort)
    of "upnp":
      return setupNat(NatUpnp, tcpPort, udpPort, clientId)
    of "pmp":
      return setupNat(NatPmp, tcpPort, udpPort, clientId)
    else:
      if nat.startsWith("extip:"):
        try:
          # any required port redirection is must be done by hand
          let ip = some(ValidIpAddress.init(nat[6..^1]))
          return (ip, tcpPort, udpPort)
        except ValueError:
          error "Not a valid IP address", address = nat[6..^1]
          quit QuitFailure
      else:
        error "Not a valid NAT option", value = nat
        quit QuitFailure
