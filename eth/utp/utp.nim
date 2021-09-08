import 
  chronos,
  ./utp_protocol

# Exemple application to interact with reference implementation server to help with implementation
# To run lib utp server:
# 1. git clone https://github.com/bittorrent/libutp.git
# 2. cd libutp
# 3. make
# 4. ./ucat -ddddd -l -p 9078 - it will run utp server on port 9078
when isMainModule:
  # TODO read client/server ports and address from cmd line or config file
  let localAddress = initTAddress("0.0.0.0", 9077)
  let utpProt = UtpProtocol.new(localAddress)

  let remoteServer = initTAddress("0.0.0.0", 9078)
  let soc = waitFor utpProt.connectTo(remoteServer)

  # Needed to wait for response from server
  waitFor(sleepAsync(100))
  waitFor utpProt.closeWait()
