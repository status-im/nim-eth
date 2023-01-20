# Copyright (c) 2019-2020 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  std/[hashes],
  nimcrypto/hash, stew/byteutils, metrics,
  ./eth_types

when defined(posix):
  import std/[posix, os]

export metrics

proc hash*(d: MDigest): Hash {.inline.} = hash(d.data)

proc parseAddress*(hexString: string): EthAddress =
  hexToPaddedByteArray[20](hexString)

proc `$`*(a: EthAddress): string =
  a.toHex()

# Block all/most signals in the current thread, so we don't interfere with regular signal
# handling elsewhere.
proc ignoreSignalsInThread*() =
  when defined(posix):
    var signalMask, oldSignalMask: Sigset

    # sigprocmask() doesn't work on macOS, for multithreaded programs
    if sigfillset(signalMask) != 0:
      echo osErrorMsg(osLastError())
      quit(QuitFailure)
    when defined(boehmgc):
      # Turns out Boehm GC needs some signals to deal with threads:
      # https://www.hboehm.info/gc/debugging.html
      const
        SIGPWR = 30
        SIGXCPU = 24
        SIGSEGV = 11
        SIGBUS = 7
      if sigdelset(signalMask, SIGPWR) != 0 or
        sigdelset(signalMask, SIGXCPU) != 0 or
        sigdelset(signalMask, SIGSEGV) != 0 or
        sigdelset(signalMask, SIGBUS) != 0:
        echo osErrorMsg(osLastError())
        quit(QuitFailure)
    if pthread_sigmask(SIG_BLOCK, signalMask, oldSignalMask) != 0:
      echo osErrorMsg(osLastError())
      quit(QuitFailure)
