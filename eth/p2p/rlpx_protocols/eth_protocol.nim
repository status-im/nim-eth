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
  chronos, stint, chronicles, eth/rlp, eth/common/eth_types,
  ../rlpx, ../private/p2p_types, ../blockchain_utils, ../../p2p

type
  NewBlockHashesAnnounce* = object
    hash: KeccakHash
    number: uint

  NewBlockAnnounce* = object
    header*: BlockHeader
    body* {.rlpInline.}: BlockBody

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

    await peer.status(protocolVersion,
                      network.networkId,
                      bestBlock.difficulty,
                      bestBlock.blockHash,
                      chain.genesisHash)

    let m = await peer.nextMsg(eth.status)
    if m.networkId == network.networkId and m.genesisHash == chain.genesisHash:
      trace "suitable peer", peer
    else:
      raise newException(UselessPeerError, "Eth handshake params mismatch")
    peer.state.initialized = true
    peer.state.bestDifficulty = m.totalDifficulty
    peer.state.bestBlockHash = m.bestHash

  proc status(peer: Peer,
              protocolVersion: uint,
              networkId: uint,
              totalDifficulty: DifficultyInt,
              bestHash: KeccakHash,
              genesisHash: KeccakHash)

  proc newBlockHashes(peer: Peer, hashes: openarray[NewBlockHashesAnnounce]) =
    discard

  proc transactions(peer: Peer, transactions: openarray[Transaction]) =
    discard

  requestResponse:
    proc getBlockHeaders(peer: Peer, request: BlocksRequest) {.gcsafe.} =
      if request.maxResults > uint64(maxHeadersFetch):
        await peer.disconnect(BreachOfProtocol)
        return

      await peer.blockHeaders(peer.network.chain.getBlockHeaders(request))

    proc blockHeaders(p: Peer, headers: openarray[BlockHeader])

  requestResponse:
    proc getBlockBodies(peer: Peer, hashes: openarray[KeccakHash]) {.gcsafe.} =
      if hashes.len > maxBodiesFetch:
        await peer.disconnect(BreachOfProtocol)
        return

      await peer.blockBodies(peer.network.chain.getBlockBodies(hashes))

    proc blockBodies(peer: Peer, blocks: openarray[BlockBody])

  proc newBlock(peer: Peer, bh: NewBlockAnnounce, totalDifficulty: DifficultyInt) =
    discard

  nextID 13

  requestResponse:
    proc getNodeData(peer: Peer, hashes: openarray[KeccakHash]) =
      await peer.nodeData(peer.network.chain.getStorageNodes(hashes))

    proc nodeData(peer: Peer, data: openarray[Blob])

  requestResponse:
    proc getReceipts(peer: Peer, hashes: openarray[KeccakHash]) =
      await peer.receipts(peer.network.chain.getReceipts(hashes))

    proc receipts(peer: Peer, receipts: openarray[Receipt])

