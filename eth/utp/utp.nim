# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import 
  chronos,
  strutils,
  os,
  ./utp_protocol

# Exemple application to interact with reference implementation server to help with implementation
# To run lib utp server:
# 1. git clone https://github.com/bittorrent/libutp.git
# 2. cd libutp
# 3. make
# 4. ./ucat -ddddd -l -p 9078 - it will run utp server on port 9078
when isMainModule:
  # TODO read client/server ports and address from cmd line or config file
  # By default runs on port 8000 unless specified
  let params = commandLineParams()
  var clientPort = 8000
  var serverPort = 9000

  for param in params:
    let flag = param.split("=")[0]
    let option = param.split("=")[1]
    if flag == "-cp" or flag == "-clientport":
      clientPort = parseInt(option)
    elif flag == "-sp" or flag == "-serverport":
      serverPort = parseInt(option)

  let localAddress = initTAddress("0.0.0.0", clientPort)
  let utpProt = UtpProtocol.new(localAddress)

  let remoteServer = initTAddress("0.0.0.0", serverPort)
  let soc = waitFor utpProt.connectTo(remoteServer)

  # Needed to wait for response from server
  waitFor(sleepAsync(100))
  waitFor utpProt.closeWait()
