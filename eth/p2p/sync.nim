import
  std/times,
  chronos

type
  FullNodeSyncer* = ref object
    chaindb: ChainDB
  FastChainSyncer = ref object
  RegularChainSyncer = ref object

# How old (in seconds) must our local head be to cause us to start with a fast-sync before we
# switch to regular-sync.
const FAST_SYNC_CUTOFF = 60 * 60 * 24


proc run(s: FullNodeSyncer) {.async.} =
  let head = await s.chaindb.getCanonicalHead()

  # We're still too slow at block processing, so if our local head is older than
  # FAST_SYNC_CUTOFF we first do a fast-sync run to catch up with the rest of the network.
  # See https://github.com/ethereum/py-evm/issues/654 for more details
  if head.timestamp < epochTime() - FAST_SYNC_CUTOFF:
      # Fast-sync chain data.
      self.logger.info("Starting fast-sync; current head: #%d", head.block_number)
      chain_syncer = FastChainSyncer(self.chaindb, self.peer_pool, self.cancel_token)
      await chain_syncer.run()

  # Ensure we have the state for our current head.
  head = await self.wait(self.chaindb.coro_get_canonical_head())
  if head.state_root != BLANK_ROOT_HASH and head.state_root not in self.base_db:
      self.logger.info(
          "Missing state for current head (#%d), downloading it", head.block_number)
      downloader = StateDownloader(
          self.base_db, head.state_root, self.peer_pool, self.cancel_token)
      await downloader.run()

  # Now, loop forever, fetching missing blocks and applying them.
  self.logger.info("Starting regular sync; current head: #%d", head.block_number)
  # This is a bit of a hack, but self.chain is stuck in the past as during the fast-sync we
  # did not use it to import the blocks, so we need this to get a Chain instance with our
  # latest head so that we can start importing blocks.
  new_chain = type(self.chain)(self.base_db)
  chain_syncer = RegularChainSyncer(
      new_chain, self.chaindb, self.peer_pool, self.cancel_token)
  await chain_syncer.run()
