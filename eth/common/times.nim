# Nimbus
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at
#     https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at
#     https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed
# except according to those terms.

type
  EthTime* = distinct uint64

# Getting the current time is not supported when compiling to bare metal
when not defined(`any`) and not defined(standalone):
  from std/times import getTime, toUnix

  proc now*(_: type EthTime): EthTime =
    getTime().toUnix.EthTime

func fromUnix*(_: type EthTime, time: int64): EthTime =
  doAssert(time >= 0)
  time.EthTime

func `+`*(a: EthTime, b: EthTime): EthTime =
  EthTime(a.uint64 + b.uint64)

func `+`*(a: EthTime, b: uint64): EthTime =
  EthTime(a.uint64 + b)

func `-`*(a: EthTime, b: EthTime): EthTime =
  EthTime(a.uint64 - b.uint64)

func `-`*(a: EthTime, b: uint64): EthTime =
  EthTime(a.uint64 - b)

func `==`*(a: EthTime, b: EthTime): bool =
  a.uint64 == b.uint64

func `==`*(a: EthTime, b: uint64): bool =
  a.uint64 == b

func `<`*(a: EthTime, b: EthTime): bool =
  a.uint64 < b.uint64

func `<`*(a: EthTime, b: uint64): bool =
  a.uint64 < b

func `<`*(a: uint64, b: EthTime): bool =
  a < b.uint64

func `<=`*(a: EthTime, b: EthTime): bool =
  a.uint64 <= b.uint64

func `$`*(x: EthTime): string =
  $(x.uint64)
