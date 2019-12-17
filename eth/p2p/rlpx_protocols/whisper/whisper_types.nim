#
#                 Whisper
#              (c) Copyright 2018-2019
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)
#

import
  algorithm, bitops, math, options, strutils, tables, times, chronicles, hashes,
  stew/[byteutils, endians2], metrics,
  nimcrypto/[bcmode, hash, keccak, rijndael, sysrand],
  eth/[keys, rlp, p2p], eth/p2p/ecies

logScope:
  topics = "whisper_types"

declarePublicCounter dropped_expired_envelopes,
  "Dropped envelopes because expired"
declarePublicCounter dropped_from_future_envelopes,
  "Dropped envelopes because of future timestamp"

const
  flagsLen = 1 ## payload flags field length, bytes
  gcmIVLen = 12 ## Length of IV (seed) used for AES
  gcmTagLen = 16 ## Length of tag used to authenticate AES-GCM-encrypted message
  padMaxLen = 256 ## payload will be padded to multiples of this by default
  signatureBits = 0b100'u8 ## payload flags signature mask
  bloomSize* = 512 div 8
  defaultFilterQueueCapacity = 64

type
  Hash* = MDigest[256]
  SymKey* = array[256 div 8, byte] ## AES256 key.
  Topic* = array[4, byte] ## 4 bytes that can be used to filter messages on.
  Bloom* = array[bloomSize, byte] ## A bloom filter that can be used to identify
  ## a number of topics that a peer is interested in.
  # XXX: nim-eth-bloom has really quirky API and fixed
  # bloom size.
  # stint is massive overkill / poor fit - a bloom filter is an array of bits,
  # not a number

  Payload* = object
    ## Payload is what goes in the data field of the Envelope.

    src*: Option[PrivateKey] ## Optional key used for signing message
    dst*: Option[PublicKey] ## Optional key used for asymmetric encryption
    symKey*: Option[SymKey] ## Optional key used for symmetric encryption
    payload*: Bytes ## Application data / message contents
    padding*: Option[Bytes] ## Padding - if unset, will automatically pad up to
                            ## nearest maxPadLen-byte boundary
  DecodedPayload* = object
    ## The decoded payload of a received message.

    src*: Option[PublicKey] ## If the message was signed, this is the public key
                            ## of the source
    payload*: Bytes ## Application data / message contents
    padding*: Option[Bytes] ## Message padding

  Envelope* = object
    ## What goes on the wire in the whisper protocol - a payload and some
    ## book-keeping
    # Don't touch field order, there's lots of macro magic that depends on it
    expiry*: uint32 ## Unix timestamp when message expires
    ttl*: uint32 ## Time-to-live, seconds - message was created at (expiry - ttl)
    topic*: Topic
    data*: Bytes ## Payload, as given by user
    nonce*: uint64 ## Nonce used for proof-of-work calculation

  Message* = object
    ## An Envelope with a few cached properties

    env*: Envelope
    hash*: Hash ## Hash, as calculated for proof-of-work
    size*: uint32 ## RLP-encoded size of message
    pow*: float64 ## Calculated proof-of-work
    bloom*: Bloom ## Filter sent to direct peers for topic-based filtering
    isP2P*: bool

  ReceivedMessage* = object
    ## A received message that matched a filter and was possible to decrypt.
    ## Contains the decoded payload and additional information.
    decoded*: DecodedPayload
    timestamp*: uint32
    ttl*: uint32
    topic*: Topic
    pow*: float64
    hash*: Hash
    dst*: Option[PublicKey]

  Queue* = object
    ## Bounded message repository
    ##
    ## Whisper uses proof-of-work to judge the usefulness of a message staying
    ## in the "cloud" - messages with low proof-of-work will be removed to make
    ## room for those with higher pow, even if they haven't expired yet.
    ## Larger messages and those with high time-to-live will require more pow.
    items*: seq[Message] ## Sorted by proof-of-work
    itemHashes*: HashSet[Message] ## For easy duplication checking
    # XXX: itemHashes is added for easy message duplication checking and for
    # easy pruning of the peer received message sets. It does have an impact on
    # adding and pruning of items however.
    # Need to give it some more thought and check where most time is lost in
    # typical cases, perhaps we are better of with one hash table (lose PoW
    # sorting however), or perhaps there is a simpler solution...

    capacity*: int ## Max messages to keep. \
    ## XXX: really big messages can cause excessive mem usage when using msg \
    ##      count

  FilterMsgHandler* = proc(msg: ReceivedMessage) {.gcsafe, closure.}

  Filter* = object
    src*: Option[PublicKey]
    privateKey*: Option[PrivateKey]
    symKey*: Option[SymKey]
    topics*: seq[Topic]
    powReq*: float64
    allowP2P*: bool

    bloom: Bloom # Cached bloom filter of all topics of filter
    handler: FilterMsgHandler
    queue: seq[ReceivedMessage]

  Filters* = Table[string, Filter]

# Utilities --------------------------------------------------------------------

proc leadingZeroBits(hash: MDigest): int =
  ## Number of most significant zero bits before the first one
  for h in hash.data:
    static: doAssert sizeof(h) == 1
    if h == 0:
      result += 8
    else:
      result += countLeadingZeroBits(h)
      break

proc calcPow*(size, ttl: uint64, hash: Hash): float64 =
  ## Whisper proof-of-work is defined as the best bit of a hash divided by
  ## encoded size and time-to-live, such that large and long-lived messages get
  ## penalized

  let bits = leadingZeroBits(hash)
  return pow(2.0, bits.float64) / (size.float64 * ttl.float64)

proc topicBloom*(topic: Topic): Bloom =
  ## Whisper uses 512-bit bloom filters meaning 9 bits of indexing - 3 9-bit
  ## indexes into the bloom are created using the first 3 bytes of the topic and
  ## complementing each byte with an extra bit from the last topic byte
  for i in 0..<3:
    var idx = uint16(topic[i])
    if (topic[3] and byte(1 shl i)) != 0: # fetch the 9'th bit from the last byte
      idx = idx + 256

    doAssert idx <= 511
    result[idx div 8] = result[idx div 8] or byte(1 shl (idx and 7'u16))

proc generateRandomID*(): string =
  var bytes: array[256 div 8, byte]
  while true: # XXX: error instead of looping?
    if randomBytes(bytes) == 256 div 8:
      result = toHex(bytes)
      break

proc `or`(a, b: Bloom): Bloom =
  for i in 0..<a.len:
    result[i] = a[i] or b[i]

proc bytesCopy*(bloom: var Bloom, b: Bytes) =
  doAssert b.len == bloomSize
  copyMem(addr bloom[0], unsafeAddr b[0], bloomSize)

proc toBloom*(topics: openArray[Topic]): Bloom =
  for topic in topics:
    result = result or topicBloom(topic)

proc bloomFilterMatch*(filter, sample: Bloom): bool =
  for i in 0..<filter.len:
    if (filter[i] or sample[i]) != filter[i]:
      return false
  return true

proc fullBloom*(): Bloom =
  ## Returns a fully set bloom filter. To be used when allowing all topics.
  # There is no setMem exported in system, assume compiler is smart enough?
  for i in 0..<result.len:
    result[i] = 0xFF

proc encryptAesGcm(plain: openarray[byte], key: SymKey,
    iv: array[gcmIVLen, byte]): Bytes =
  ## Encrypt using AES-GCM, making sure to append tag and iv, in that order
  var gcm: GCM[aes256]
  result = newSeqOfCap[byte](plain.len + gcmTagLen + iv.len)
  result.setLen plain.len
  gcm.init(key, iv, [])
  gcm.encrypt(plain, result)
  var tag: array[gcmTagLen, byte]
  gcm.getTag(tag)
  result.add tag
  result.add iv

proc decryptAesGcm(cipher: openarray[byte], key: SymKey): Option[Bytes] =
  ## Decrypt AES-GCM ciphertext and validate authenticity - assumes
  ## cipher-tag-iv format of the buffer
  if cipher.len < gcmTagLen + gcmIVLen:
    debug "cipher missing tag/iv", len = cipher.len
    return
  let plainLen = cipher.len - gcmTagLen - gcmIVLen
  var gcm: GCM[aes256]
  var res = newSeq[byte](plainLen)
  let iv = cipher[^gcmIVLen .. ^1]
  let tag = cipher[^(gcmIVLen + gcmTagLen) .. ^(gcmIVLen + 1)]
  gcm.init(key, iv, [])
  gcm.decrypt(cipher[0 ..< ^(gcmIVLen + gcmTagLen)], res)
  var tag2: array[gcmTagLen, byte]
  gcm.getTag(tag2)

  if tag != tag2:
    debug "cipher tag mismatch", len = cipher.len, tag, tag2
    return
  return some(res)

# Payloads ---------------------------------------------------------------------

# Several differences between geth and parity - this code is closer to geth
# simply because that makes it closer to EIP 627 - see also:
# https://github.com/paritytech/parity-ethereum/issues/9652

proc encode*(self: Payload): Option[Bytes] =
  ## Encode a payload according so as to make it suitable to put in an Envelope
  ## The format follows EIP 627 - https://eips.ethereum.org/EIPS/eip-627

  # XXX is this limit too high? We could limit it here but the protocol
  #     technically supports it..
  if self.payload.len >= 256*256*256:
    notice "Payload exceeds max length", len = self.payload.len
    return

  # length of the payload length field :)
  let payloadLenLen =
    if self.payload.len >= 256*256: 3'u8
    elif self.payload.len >= 256: 2'u8
    else: 1'u8

  let signatureLen =
    if self.src.isSome(): keys.RawSignatureSize
    else: 0

  # useful data length
  let dataLen = flagsLen + payloadLenLen.int + self.payload.len + signatureLen

  let padLen =
    if self.padding.isSome(): self.padding.get().len
    # is there a reason why 256 bytes are padded when the dataLen is 256?
    else: padMaxLen - (dataLen mod padMaxLen)

  # buffer space that we need to allocate
  let totalLen = dataLen + padLen

  var plain = newSeqOfCap[byte](totalLen)

  let signatureFlag =
    if self.src.isSome(): signatureBits
    else: 0'u8

  # byte 0: flags with payload length length and presence of signature
  plain.add payloadLenLen or signatureFlag

  # next, length of payload - little endian (who comes up with this stuff? why
  # can't the world just settle on one endian?)
  let payloadLenLE = self.payload.len.uint32.toBytesLE

  # No, I have no love for nim closed ranges - such a mess to remember the extra
  # < or risk off-by-ones when working with lengths..
  plain.add payloadLenLE[0..<payloadLenLen]
  plain.add self.payload

  if self.padding.isSome():
    plain.add self.padding.get()
  else:
    var padding = newSeq[byte](padLen)
    if randomBytes(padding) != padLen:
      notice "Generation of random padding failed"
      return

    plain.add padding

  if self.src.isSome(): # Private key present - signature requested
    let hash = keccak256.digest(plain)
    var sig: Signature
    let err = signRawMessage(hash.data, self.src.get(), sig)
    if err != EthKeysStatus.Success:
      notice "Signing message failed", err
      return

    plain.add sig.getRaw()

  if self.dst.isSome(): # Asymmetric key present - encryption requested
    var res = newSeq[byte](eciesEncryptedLength(plain.len))
    let err = eciesEncrypt(plain, res, self.dst.get())
    if err != EciesStatus.Success:
      notice "Encryption failed", err
      return
    return some(res)

  if self.symKey.isSome(): # Symmetric key present - encryption requested
    var iv: array[gcmIVLen, byte]
    if randomBytes(iv) != gcmIVLen:
      notice "Generation of random IV failed"
      return

    return some(encryptAesGcm(plain, self.symKey.get(), iv))

  # No encryption!
  return some(plain)

proc decode*(data: openarray[byte], dst = none[PrivateKey](),
    symKey = none[SymKey]()): Option[DecodedPayload] =
  ## Decode data into payload, potentially trying to decrypt if keys are
  ## provided

  # Careful throughout - data coming from unknown source - malformatted data
  # expected

  var res: DecodedPayload

  var plain: Bytes
  if dst.isSome():
    # XXX: eciesDecryptedLength is pretty fragile, API-wise.. is this really the
    #      way to check for errors / sufficient length?
    let plainLen = eciesDecryptedLength(data.len)
    if plainLen < 0:
      debug "Not enough data to decrypt", len = data.len
      return

    plain.setLen(eciesDecryptedLength(data.len))
    if eciesDecrypt(data, plain, dst.get()) != EciesStatus.Success:
      debug "Couldn't decrypt using asymmetric key", len = data.len
      return
  elif symKey.isSome():
    let tmp = decryptAesGcm(data, symKey.get())
    if tmp.isNone():
      debug "Couldn't decrypt using symmetric key", len = data.len
      return

    plain = tmp.get()
  else: # No encryption!
    plain = @data

  if plain.len < 2: # Minimum 1 byte flags, 1 byte payload len
    debug "Missing flags or payload length", len = plain.len
    return

  var pos = 0

  let payloadLenLen = int(plain[pos] and 0b11'u8)
  let hasSignature = (plain[pos] and 0b100'u8) != 0

  pos += 1

  if plain.len < pos + payloadLenLen:
    debug "Missing payload length", len = plain.len, pos, payloadLenLen
    return

  var payloadLenLE: array[4, byte]

  for i in 0..<payloadLenLen: payloadLenLE[i] = plain[pos + i]
  pos += payloadLenLen

  let payloadLen = int(fromBytesLE(uint32, payloadLenLE))
  if plain.len < pos + payloadLen:
    debug "Missing payload", len = plain.len, pos, payloadLen
    return

  res.payload = plain[pos ..< pos + payloadLen]

  pos += payloadLen

  if hasSignature:
    if plain.len < (keys.RawSignatureSize + pos):
      debug "Missing expected signature", len = plain.len
      return

    let sig = plain[^keys.RawSignatureSize .. ^1]
    let hash = keccak256.digest(plain[0 ..< ^keys.RawSignatureSize])
    var key: PublicKey
    let err = recoverSignatureKey(sig, hash.data, key)
    if err != EthKeysStatus.Success:
      debug "Failed to recover signature key", err
      return
    res.src = some(key)

  if hasSignature:
    if plain.len > pos + keys.RawSignatureSize:
      res.padding = some(plain[pos .. ^(keys.RawSignatureSize+1)])
  else:
    if plain.len > pos:
      res.padding = some(plain[pos .. ^1])

  return some(res)

# Envelopes --------------------------------------------------------------------

proc valid*(self: Envelope, now = epochTime()): bool =
  if self.expiry.float64 < now: # expired
    dropped_expired_envelopes.inc()
    return false
  if self.ttl <= 0: # this would invalidate pow calculation
    dropped_expired_envelopes.inc()
    return false

  let created = self.expiry - self.ttl
  if created.float64 > (now + 2.0): # created in the future
    dropped_from_future_envelopes.inc()
    return false

  return true

proc len(self: Envelope): int = 20 + self.data.len

proc toShortRlp*(self: Envelope): Bytes =
  ## RLP-encoded message without nonce is used during proof-of-work calculations
  rlp.encodeList(self.expiry, self.ttl, self.topic, self.data)

proc toRlp(self: Envelope): Bytes =
  ## What gets sent out over the wire includes the nonce
  rlp.encode(self)

proc minePow*(self: Envelope, seconds: float, bestBitTarget: int = 0): (uint64, Hash) =
  ## For the given envelope, spend millis milliseconds to find the
  ## best proof-of-work and return the nonce
  let bytes = self.toShortRlp()

  var ctx: keccak256
  ctx.init()
  ctx.update(bytes)

  var bestBit: int = 0

  let mineEnd = epochTime() + seconds

  var i: uint64
  while epochTime() < mineEnd or bestBit == 0: # At least one round
    var tmp = ctx # copy hash calculated so far - we'll reuse that for each iter
    tmp.update(i.toBytesBE())
    # XXX:a random nonce here would not leak number of iters
    let hash = tmp.finish()
    let zeroBits = leadingZeroBits(hash)
    if zeroBits > bestBit: # XXX: could also compare hashes as numbers instead
      bestBit = zeroBits
      result = (i, hash)
      if bestBitTarget > 0 and bestBit >= bestBitTarget:
        break

    i.inc

proc calcPowHash*(self: Envelope): Hash =
  ## Calculate the message hash, as done during mining - this can be used to
  ## verify proof-of-work

  let bytes = self.toShortRlp()

  var ctx: keccak256
  ctx.init()
  ctx.update(bytes)
  ctx.update(self.nonce.toBytesBE())
  return ctx.finish()

# Messages ---------------------------------------------------------------------

proc cmpPow(a, b: Message): int =
  ## Biggest pow first, lowest at the end (for easy popping)
  if a.pow > b.pow: 1
  elif a.pow == b.pow: 0
  else: -1

proc initMessage*(env: Envelope, powCalc = true): Message =
  result.env = env
  result.size = env.toRlp().len().uint32 # XXX: calc len without creating RLP
  result.bloom = topicBloom(env.topic)
  if powCalc:
    result.hash = env.calcPowHash()
    result.pow = calcPow(result.env.len.uint32, result.env.ttl, result.hash)
    trace "Message PoW", pow = result.pow.formatFloat(ffScientific)

proc hash*(msg: Message): hashes.Hash = hash(msg.hash.data)

# NOTE: Hashing and leading zeroes calculation is now the same between geth,
# parity and this implementation.
# However, there is still a difference in the size calculation.
# See also here: https://github.com/ethereum/go-ethereum/pull/19753
# This implementation is not conform EIP-627 as we do not use the size of the
# RLP-encoded envelope, but the size of the envelope object itself.
# This is done to be able to correctly calculate the bestBitTarget.
# Other options would be:
# - work directly with powTarget in minePow, but this requires recalculation of
#   rlp size + calcPow
# - Use worst case size of envelope nonce
# - Mine PoW for x interval, calcPow of best result, if target not met .. repeat
proc sealEnvelope*(msg: var Message, powTime: float, powTarget: float): bool =
  let size = msg.env.len
  if powTarget > 0:
    let x = powTarget * size.float * msg.env.ttl.float
    var bestBitTarget: int
    if x <= 1: # log() would return negative numbers or 0
      bestBitTarget = 1
    else:
      bestBitTarget = ceil(log(x, 2)).int
    (msg.env.nonce, msg.hash) = msg.env.minePow(powTime, bestBitTarget)
  else:
    # If no target is set, we are certain of executed powTime
    msg.env.expiry += powTime.uint32
    (msg.env.nonce, msg.hash) = msg.env.minePow(powTime)

  msg.pow = calcPow(size.uint32, msg.env.ttl, msg.hash)
  trace "Message PoW", pow = msg.pow
  if msg.pow < powTarget:
     return false

  return true

# Queues -----------------------------------------------------------------------

proc initQueue*(capacity: int): Queue =
  result.items = newSeqOfCap[Message](capacity)
  result.capacity = capacity
  result.itemHashes.init()

proc prune*(self: var Queue) {.raises: [].} =
  ## Remove items that are past their expiry time
  let now = epochTime().uint32

  # keepIf code + pruning of hashset
  var pos = 0
  for i in 0 ..< len(self.items):
    if self.items[i].env.expiry > now:
      if pos != i:
        shallowCopy(self.items[pos], self.items[i])
      inc(pos)
    else: self.itemHashes.excl(self.items[i])
  setLen(self.items, pos)

proc add*(self: var Queue, msg: Message): bool =
  ## Add a message to the queue.
  ## If we're at capacity, we will be removing, in order:
  ## * expired messages
  ## * lowest proof-of-work message - this may be `msg` itself!

  if self.items.len >= self.capacity:
    self.prune() # Only prune if needed

    if self.items.len >= self.capacity:
      # Still no room - go by proof-of-work quantity
      let last = self.items[^1]

      if last.pow > msg.pow or
        (last.pow == msg.pow and last.env.expiry > msg.env.expiry):
        # The new message has less pow or will expire earlier - drop it
        return false

      self.items.del(self.items.len() - 1)
      self.itemHashes.excl(last)

  # check for duplicate
  if self.itemHashes.containsOrIncl(msg):
    return false
  else:
    self.items.insert(msg, self.items.lowerBound(msg, cmpPow))
    return true

# Filters ----------------------------------------------------------------------
proc newFilter*(src = none[PublicKey](), privateKey = none[PrivateKey](),
                symKey = none[SymKey](), topics: seq[Topic] = @[],
                powReq = 0.0, allowP2P = false): Filter =
  # Zero topics will give an empty bloom filter which is fine as this bloom
  # filter is only used to `or` with existing/other bloom filters. Not to do
  # matching.
  Filter(src: src, privateKey: privateKey, symKey: symKey, topics: topics,
         powReq: powReq, allowP2P: allowP2P, bloom: toBloom(topics))

proc subscribeFilter*(filters: var Filters, filter: Filter,
                      handler:FilterMsgHandler = nil): string =
  # NOTE: Should we allow a filter without a key? Encryption is mandatory in v6?
  # Check if asymmetric _and_ symmetric key? Now asymmetric just has precedence.
  let id = generateRandomID()
  var filter = filter
  if handler.isNil():
    filter.queue = newSeqOfCap[ReceivedMessage](defaultFilterQueueCapacity)
  else:
    filter.handler = handler

  filters.add(id, filter)
  debug "Filter added", filter = id
  return id

proc notify*(filters: var Filters, msg: Message) {.gcsafe.} =
 var decoded: Option[DecodedPayload]
 var keyHash: Hash
 var dst: Option[PublicKey]

 for filter in filters.mvalues:
   if not filter.allowP2P and msg.isP2P:
     continue

   # if message is direct p2p PoW doesn't matter
   if msg.pow < filter.powReq and not msg.isP2P:
     continue

   if filter.topics.len > 0:
     if msg.env.topic notin filter.topics:
       continue

   # Decode, if already decoded previously check if hash of key matches
   if decoded.isNone():
     decoded = decode(msg.env.data, dst = filter.privateKey,
                      symKey = filter.symKey)
     if decoded.isNone():
       continue
     if filter.privateKey.isSome():
       keyHash = keccak256.digest(filter.privateKey.get().data)
       # TODO: Get rid of the hash and just use pubkey to compare?
       dst = some(getPublicKey(filter.privateKey.get()))
     elif filter.symKey.isSome():
       keyHash = keccak256.digest(filter.symKey.get())
     # else:
       # NOTE: In this case the message was not encrypted
   else:
     if filter.privateKey.isSome():
       if keyHash != keccak256.digest(filter.privateKey.get().data):
         continue
     elif filter.symKey.isSome():
       if keyHash != keccak256.digest(filter.symKey.get()):
         continue
     # else:
       # NOTE: In this case the message was not encrypted

   # When decoding is done we can check the src (signature)
   if filter.src.isSome():
     let src: Option[PublicKey] = decoded.get().src
     if not src.isSome():
       continue
     elif src.get() != filter.src.get():
       continue

   let receivedMsg = ReceivedMessage(decoded: decoded.get(),
                                     timestamp: msg.env.expiry - msg.env.ttl,
                                     ttl: msg.env.ttl,
                                     topic: msg.env.topic,
                                     pow: msg.pow,
                                     hash: msg.hash,
                                     dst: dst)
   # Either run callback or add to queue
   if filter.handler.isNil():
     filter.queue.insert(receivedMsg)
   else:
     filter.handler(receivedMsg)

proc getFilterMessages*(filters: var Filters, filterId: string): seq[ReceivedMessage] =
  result = @[]
  if filters.contains(filterId):
    if filters[filterId].handler.isNil():
      shallowCopy(result, filters[filterId].queue)
      filters[filterId].queue =
        newSeqOfCap[ReceivedMessage](defaultFilterQueueCapacity)

proc toBloom*(filters: Filters): Bloom =
  for filter in filters.values:
    if filter.topics.len > 0:
      result = result or filter.bloom
