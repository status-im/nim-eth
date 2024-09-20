# eth
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

## 20-byte ethereum account address, as derived from the keypair controlling it
## https://ethereum.org/en/developers/docs/accounts/#account-creation

import std/[typetraits, hashes], "."/[base_types, eth_hash]

export hashes

type Address* = distinct Bytes20
  ## https://github.com/ethereum/execution-specs/blob/51fac24740e662844446439ceeb96a460aae0ba0/src/ethereum/paris/fork_types.py#L28

const zeroAddress* = system.default(Address)
  ## Address consisting of all zeroes.
  ## Transactions to zeroAddress are legitimate transfers to that account, not
  ## contract creations.  They are used to "burn" Eth.  People also send Eth to
  ## address zero by accident, unrecoverably, due to poor user interface issues.

template to*(v: array[20, byte], _: type Address): Address =
  Address(v)

template data*(v: Address): array[20, byte] =
  distinctBase(v)

template default*(_: type Address): Address =
  # Avoid bad codegen where fixed bytes are zeroed byte-by-byte at call site
  zeroAddress

func `==`*(a, b: Address): bool {.borrow.}

func hash*(a: Address): Hash {.inline.} =
  # Addresses are more or less random so we should not need a fancy mixing
  # function
  var a0 {.noinit.}, a1 {.noinit.}: uint64
  var a2 {.noinit.}: uint32

  copyMem(addr a0, unsafeAddr a.data[0], sizeof(a0))
  copyMem(addr a1, unsafeAddr a.data[8], sizeof(a1))
  copyMem(addr a2, unsafeAddr a.data[16], sizeof(a2))

  cast[Hash](a0 + a1 + uint64(a2))

func toHex*(a: Address): string {.borrow.}
func to0xHex*(a: Address): string {.borrow.}
func `$`*(a: Address): string {.borrow.}

func fromHex*(_: type Address, s: openArray[char]): Address {.raises: [ValueError].} =
  Address(Bytes20.fromHex(s))

template to*(s: static string, _: type Address): Address =
  const hash = Address.fromHex(s)
  hash

template address*(s: static string): Address =
  s.to(Address)

func toChecksum0xHex*(a: Address): string =
  ## Convert the address to 0x-prefixed mixed-case EIP-55 format
  let
    # TODO avoid memory allocations here
    hhash1 = a.toHex()
    hhash2 = keccak256(hhash1).toHex()
  result = newStringOfCap(hhash2.len + 2)
  result.add "0x"

  for i, c in hhash1:
    if hhash2[i] >= '0' and hhash2[i] <= '7':
      result.add c
    else:
      if c >= '0' and c <= '9':
        result.add c
      else:
        result.add chr(ord(c) - ord('a') + ord('A'))

func hasValidChecksum*(_: type Address, a: string): bool =
  ## Validate checksumable mixed-case address (EIP-55).
  let address =
    try:
      Address.fromHex(a)
    except ValueError:
      return false
  a == address.toChecksum0xHex()
