# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import 
  chronos, stew/byteutils,
  ./utp_router,
  ./utp_socket,
  ./utp_protocol

# Exemple application to interact with reference implementation server to help with implementation
# To run lib utp server:
# 1. git clone https://github.com/bittorrent/libutp.git
# 2. cd libutp
# 3. make
# 4. ./ucat -ddddd -l -p 9078 - it will run utp server on port 9078
when isMainModule:
  proc echoIncomingSocketCallBack(): AcceptConnectionCallback[TransportAddress] =
    return (
      proc (server: UtpRouter[TransportAddress], client: UtpSocket[TransportAddress]): Future[void] {.gcsafe, raises: [Defect].} = 
        echo "received incoming connection"
        let fakeFuture = newFuture[void]()
        fakeFuture.complete()
        return fakeFuture
    )
  # TODO read client/server ports and address from cmd line or config file
  let localAddress = initTAddress("0.0.0.0", 9077)
  let utpProt = UtpProtocol.new(echoIncomingSocketCallBack(), localAddress)

  let remoteServer = initTAddress("127.0.0.1", 9078)
  let soc = waitFor utpProt.connectTo(remoteServer)

  doAssert(soc.numPacketsInOutGoingBuffer() == 0)

  let helloUtp = "Helllo from nim implementation"
  let bytes = helloUtp.toBytes()

  discard waitFor soc.write(bytes)

  waitFor(sleepAsync(milliseconds(1000)))

  discard waitFor soc.write(bytes)

  runForever()

  waitFor utpProt.closeWait()
