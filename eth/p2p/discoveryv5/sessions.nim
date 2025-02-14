# nim-eth - Node Discovery Protocol v5
# Copyright (c) 2020-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
#
## Session cache as mentioned at
## https://github.com/ethereum/devp2p/blob/5713591d0366da78a913a811c7502d9ca91d29a8/discv5/discv5-theory.md#session-cache
##

{.push raises: [].}

import
  std/net,
  bearssl/rand,
  stint, stew/endians2,
  ./node, minilru

export minilru

const
  aesKeySize* = 128 div 8
  gcmNonceSize* = 12
  keySize =
    sizeof(NodeId) +
    16 + # max size of ip address (ipv6)
    2 # size of port

type
  AESGCMNonce* = array[gcmNonceSize, byte]
  AesKey* = array[aesKeySize, byte]
  SessionKey* = array[keySize, byte]
  Session* = ref object
    readKey*: AesKey
    writeKey*: AesKey
    counter*: uint32

  Sessions* = LruCache[SessionKey, Session]

func nextNonce*(session: Session, rng: var HmacDrbgContext): AESGCMNonce =
  # Generate nonce that is a concatenation of a 32-bit counter and a 64-bit random value.
  # This is as is recommended in the discv5 spec:
  # https://github.com/ethereum/devp2p/blob/5713591d0366da78a913a811c7502d9ca91d29a8/discv5/discv5-theory.md#session-cache
  # The counter MUST be incremented after each use of the session writeKey.
  # The recommendation when using 96-bit random nonce value is:
  # "The total number of invocations of the authenticated encryption function shall not
  # exceed 2^32, including all IV lengths and all instances of the authenticated
  # encryption function with the given key."
  # See NIST SP 800-38D, section 8:
  # https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
  # For the usage in discv5, this translates to 2^32 messages per session.
  # A 32-bit counter + 64-bit random value nonce should increase that to 2^48 messages.
  # The random component is added (opposed to a full 96-bit counter) to safeguard
  # against nonce reuse in the case of counter cache/storage bugs.
  var nonce: AESGCMNonce
  nonce[0 .. 3] = session.counter.toBytesBE()
  nonce[4 ..^ 1] = rng.generate(array[gcmNonceSize - 4, byte])

  session.counter.inc()

  nonce

func makeKey(id: NodeId, address: Address): SessionKey =
  var pos = 0
  result[pos ..< pos+sizeof(id)] = toBytesBE(id)
  pos.inc(sizeof(id))
  case address.ip.family
  of IpAddressFamily.IpV4:
    result[pos ..< pos+sizeof(address.ip.address_v4)] = address.ip.address_v4
  of IpAddressFamily.IpV6:
    result[pos ..< pos+sizeof(address.ip.address_v6)] = address.ip.address_v6
  pos.inc(sizeof(address.ip.address_v6))
  result[pos ..< pos+sizeof(address.port)] = toBytesBE(address.port.uint16)

func store*(s: var Sessions, id: NodeId, address: Address, session: Session) =
  s.put(makeKey(id, address), session)

func store*(s: var Sessions, id: NodeId, address: Address, r, w: AesKey) =
  s.store(id, address, Session(readKey: r, writeKey: w, counter: 0))

func load*(s: var Sessions, id: NodeId, address: Address): Opt[Session] =
  s.get(makeKey(id, address))

func loadReadKey*(s: var Sessions, id: NodeId, address: Address): Opt[AesKey] =
  let res = s.get(makeKey(id, address))
  if res.isSome():
    Opt.some(res.value().readKey)
  else:
    Opt.none(AesKey)

func del*(s: var Sessions, id: NodeId, address: Address) =
  s.del(makeKey(id, address))
