import
  eth/common/[eth_types, state_accessors]

# TODO: Perhaps we can move this to eth-common

proc getBlockHeaders*(db: AbstractChainDB,
                      req: BlocksRequest): seq[BlockHeader] {.gcsafe.} =
  result = newSeqOfCap[BlockHeader](req.maxResults)

  var foundBlock: BlockHeader
  if db.getBlockHeader(req.startBlock, foundBlock):
    result.add foundBlock

    while uint64(result.len) < req.maxResults:
      if not req.reverse:
        if not db.getSuccessorHeader(foundBlock, foundBlock, req.skip):
          break
      else:
        if not db.getAncestorHeader(foundBlock, foundBlock, req.skip):
          break
      result.add foundBlock


template fetcher*(fetcherName, fetchingFunc, InputType, ResultType: untyped) =
  proc fetcherName*(db: AbstractChainDB,
                    lookups: openarray[InputType]): seq[ResultType] {.gcsafe.} =
    for lookup in lookups:
      let fetched = fetchingFunc(db, lookup)
      if fetched.hasData:
        # TODO: should there be an else clause here.
        # Is the peer responsible of figuring out that
        # some of the requested items were not found?
        result.add deref(fetched)

fetcher getContractCodes,  getContractCode,  ContractCodeRequest, Blob
fetcher getBlockBodies,    getBlockBody,     KeccakHash,    BlockBody
fetcher getStorageNodes,   getStorageNode,   KeccakHash,    Blob
fetcher getReceipts,       getReceipt,       KeccakHash,    Receipt
fetcher getProofs,         getProof,         ProofRequest,  Blob
fetcher getHeaderProofs,   getHeaderProof,   ProofRequest,  Blob

proc getHelperTrieProofs*(db: AbstractChainDB,
                          reqs: openarray[HelperTrieProofRequest],
                          outNodes: var seq[Blob], outAuxData: var seq[Blob]) =
  discard

