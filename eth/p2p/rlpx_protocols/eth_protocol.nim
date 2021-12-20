#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)
#

## This module implements the Ethereum Wire Protocol:
## https://github.com/ethereum/wiki/wiki/Ethereum-Wire-Protocol

import
  chronos, stint, chronicles,
  ../../rlp, ../../common/eth_types, ../../p2p,
  ../rlpx, ../private/p2p_types, ../blockchain_utils

type
  NewBlockHashesAnnounce* = object
    hash: KeccakHash
    number: uint

  NewBlockAnnounce* = object
    header*: BlockHeader
    txs*:    seq[Transaction]
    uncles*: seq[BlockHeader]

  PeerState = ref object
    initialized*: bool
    bestBlockHash*: KeccakHash
    bestDifficulty*: DifficultyInt

const
  maxStateFetch* = 384
  maxBodiesFetch* = 128
  maxReceiptsFetch* = 256
  maxHeadersFetch* = 192
  protocolVersion* = 63

p2pProtocol eth(version = protocolVersion,
                peerState = PeerState,
                useRequestIds = false):

  onPeerConnected do (peer: Peer):
    let
      network = peer.network
      chain = network.chain
      bestBlock = chain.getBestBlockHeader

    let m = await peer.status(protocolVersion,
                              network.networkId,
                              bestBlock.difficulty,
                              bestBlock.blockHash,
                              chain.genesisHash,
                              timeout = chronos.seconds(10))

    if m.networkId == network.networkId and m.genesisHash == chain.genesisHash:
      trace "suitable peer", peer
    else:
      raise newException(UselessPeerError, "Eth handshake params mismatch")
    peer.state.initialized = true
    peer.state.bestDifficulty = m.totalDifficulty
    peer.state.bestBlockHash = m.bestHash

  handshake:
    proc status(peer: Peer,
                protocolVersion: uint,
                networkId: NetworkId,
                totalDifficulty: DifficultyInt,
                bestHash: KeccakHash,
                genesisHash: KeccakHash)

  proc newBlockHashes(peer: Peer, hashes: openArray[NewBlockHashesAnnounce]) =
    discard

  proc transactions(peer: Peer, transactions: openArray[Transaction]) =
    discard

  requestResponse:
    proc getBlockHeaders(peer: Peer, request: BlocksRequest) {.gcsafe.} =
      if request.maxResults > uint64(maxHeadersFetch):
        await peer.disconnect(BreachOfProtocol)
        return

      await response.send(peer.network.chain.getBlockHeaders(request))

    proc blockHeaders(p: Peer, headers: openArray[BlockHeader])

  requestResponse:
    proc getBlockBodies(peer: Peer, hashes: openArray[KeccakHash]) {.gcsafe.} =
      if hashes.len > maxBodiesFetch:
        await peer.disconnect(BreachOfProtocol)
        return

      await response.send(peer.network.chain.getBlockBodies(hashes))

    proc blockBodies(peer: Peer, blocks: openArray[BlockBody])

  proc newBlock(peer: Peer, bh: NewBlockAnnounce, totalDifficulty: DifficultyInt) =
    discard

  nextID 13

  requestResponse:
    proc getNodeData(peer: Peer, hashes: openArray[KeccakHash]) =
      await response.send(peer.network.chain.getStorageNodes(hashes))

    proc nodeData(peer: Peer, data: openArray[Blob])

  requestResponse:
    proc getReceipts(peer: Peer, hashes: openArray[KeccakHash]) = discard
      # TODO: implement `getReceipts` and reactivate this code
      # await response.send(peer.network.chain.getReceipts(hashes))

    proc receipts(peer: Peer, receipts: openArray[Receipt])

