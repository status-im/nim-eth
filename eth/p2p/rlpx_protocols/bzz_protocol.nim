import
  chronos, chronicles, eth/p2p

# Limited bzz protocol that allows for doing a handshake with a peer running
# ethersphere/swarm client rev. c535b271536d0dee5bd97c2541ca32a42f272d4f

const
  bzzVersion = 12
  hiveVersion = 10
  swarmNetworkId* = 4
  # Faking our capabilities to make handshake work, "bit" 0, 1, 4, 5, 15.
  supportedCapabilities = [1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]

type
  # Need object (or extra seq) here as swarm expects list(list(Capability))
  Capabilities = object
    caps: seq[Capability]

  Capability = object
    id: uint
    # Swarm expects here list(bool), thus bool or int (values <= 1 byte, as rlp
    # writer has currently no int8 support). Guess this could be a bitvector.
    # Also looks like per id the list can have a different size, so lets stick
    # with seq instead of array.
    value: seq[int]

  OverlayAddress = array[32, byte]

  AddressData = object
    oaddr: OverlayAddress
    uaddr: string

  Handshake = object
    version: uint
    networkId: uint
    addressData: AddressData
    capabilities: Capabilities

  BzzNetwork = ref object
    thisENode*: ENode

p2pProtocol Hive(version = hiveVersion,
                 rlpxName = "hive"):

  proc peersMsg(peer: Peer)
  proc subPeersMsg(peer:Peer)

  onPeerConnected do (peer: Peer):
    debug "Hive peer connected"

proc initProtocolState*(network: BzzNetwork, node: EthereumNode) {.gcsafe.} =
  network.thisENode = node.toENode()

p2pProtocol Bzz(version = bzzVersion,
                rlpxName = "bzz",
                networkState = BzzNetwork):

  handshake:
    proc hs(peer: Peer, hs: Handshake) =
      trace "Incoming bzz handshake", version = hs.version,
                                      addressData = hs.addressData

  onPeerConnected do (peer: Peer):
    debug "Bzz peer connected"

    # Now all zeroes, this needs to be the Hash of the ECDSA Public Key
    # of the used Ethereum account
    var oaddr: OverlayAddress
    let
      # TODO: could do ENode RLP serialisation
      # Why do we need to send the ENode? Doesn't the peer already have this?
      # Or should it be a different one?
      uaddr = $peer.networkState.thisENode
      addressData = AddressData(oaddr: oaddr,
                                uaddr: uaddr)

      caps = Capabilities(caps: @[Capability(id: 0,
                                             value: @supportedCapabilities)])
      handshake = Handshake(version: bzzVersion,
                            networkId: swarmNetworkId,
                            addressData: addressData,
                            capabilities: caps)

      m = await peer.hs(handshake, timeout = chronos.seconds(10))
      # TODO: validate the handshake...
