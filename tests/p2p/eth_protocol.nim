import
  chronos,
  ../../eth/[p2p, common]

# for testing purpose
# real eth protocol implementation is in nimbus-eth1 repo

type
  PeerState = ref object
    initialized*: bool

p2pProtocol eth(version = 63,
                peerState = PeerState,
                useRequestIds = false):

  onPeerConnected do (peer: Peer):
    let
      network = peer.network

    let m = await peer.status(63,
                              network.networkId,
                              0.u256,
                              Hash256(),
                              Hash256(),
                              timeout = chronos.seconds(10))

  handshake:
    proc status(peer: Peer,
                protocolVersion: uint,
                networkId: NetworkId,
                totalDifficulty: DifficultyInt,
                bestHash: KeccakHash,
                genesisHash: KeccakHash)

  requestResponse:
    proc getBlockHeaders(peer: Peer, request: openArray[KeccakHash]) {.gcsafe.} = discard
    proc blockHeaders(p: Peer, headers: openArray[BlockHeader])

  requestResponse:
    proc getBlockBodies(peer: Peer, hashes: openArray[KeccakHash]) {.gcsafe.} = discard
    proc blockBodies(peer: Peer, blocks: openArray[BlockBody])

  nextID 13

  requestResponse:
    proc getNodeData(peer: Peer, hashes: openArray[KeccakHash]) = discard
    proc nodeData(peer: Peer, data: openArray[Blob])

  requestResponse:
    proc getReceipts(peer: Peer, hashes: openArray[KeccakHash]) = discard
    proc receipts(peer: Peer, receipts: openArray[Receipt])
