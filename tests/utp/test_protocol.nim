# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  chronos,
  testutils/unittests,
  ../../eth/utp/utp_protocol,
  ../../eth/keys
  
procSuite "Utp protocol tests":
  let rng = newRng()

  asyncTest "Success connect to remote host":
    let address = initTAddress("127.0.0.1", 9079)
    let utpProt1 = UtpProtocol.new(address)

    let address1 = initTAddress("127.0.0.1", 9080)
    let utpProt2 = UtpProtocol.new(address1)

    let sock = await utpProt1.connectTo(address1)

    check:
      sock.isConnected()
      # after successful connection outgoing buffer should be empty as syn packet
      # should be correctly acked
      sock.numPacketsInOutGoingBuffer() == 0

    await utpProt1.closeWait()
    await utpProt2.closeWait()
