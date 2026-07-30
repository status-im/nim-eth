# eth
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

## The BoringSSL-derived Keccak-256, retained as the independent
## implementation that `tests/keccak` differentially tests `keccak_xkcp`
## against. Not used in production - `keccak.nim` is the entry point.

import
  std/[os, strutils]

from nimcrypto/hash import MDigest
export MDigest

const
  srcPath = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0]

{.pragma: kheader, header: srcPath & "/keccak_boringssl.h".}
{.passc: "-I" & srcPath.}
{.compile: srcPath & "/keccak_boringssl.c".}

type
  Keccak256* {.importc: "keccak_st", kheader.} = object

func init(h: var Keccak256) {.cdecl, importc: "keccak_init", kheader.}
func finish(h: var Keccak256, val: var openArray[byte]) {.cdecl, importc: "keccak_finish", kheader.}
func update*(h: var Keccak256, data: openArray[byte]) {.cdecl, importc: "keccak_update", kheader.}
func update*(h: var Keccak256, data: openArray[char]) {.cdecl, importc: "keccak_update_char", kheader.}
func keccak256_20*(data: ptr byte, output: ptr byte) {.cdecl, importc: "keccak256_20", kheader.}
func keccak256_32*(data: ptr byte, output: ptr byte) {.cdecl, importc: "keccak256_32", kheader.}

template clear*(h: var Keccak256) =
  init(h)

{.push inline, noinit, gcsafe, stackTrace:off.}

func init*(_: type Keccak256): Keccak256 =
  result.init()

func digest*(_: type Keccak256, data: openArray[byte]): MDigest[256] =
  var ctx = Keccak256.init()
  ctx.update(data)
  ctx.finish(result.data)

func finish*(h: var Keccak256): MDigest[256] =
  h.finish(result.data)

func keccak256_20*(data: openArray[byte]): MDigest[256] =
  keccak256_20(data[0].addr, result.data[0].addr)

func keccak256_32*(data: openArray[byte]): MDigest[256] =
  keccak256_32(data[0].addr, result.data[0].addr)

{.pop.}
