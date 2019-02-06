#
#                 Ethereum P2P
#              (c) Copyright 2018
#       Status Research & Development GmbH
#
#            Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#            MIT license (LICENSE-MIT)

import
  sequtils, options, strutils, parseopt, chronos,
  eth/[keys, rlp, p2p], eth/p2p/rlpx_protocols/[whisper_protocol],
  eth/p2p/[discovery, enode, peer_pool]

const
  DefaultListeningPort = 30303
  Usage = """Usage:
  tssh_client [options]
Options:
  -p --port                 Listening port
  --post                    Post messages
  --watch                   Install filters
  --mainnet                 Connect to main network (default local private)
  --local                   Only local loopback
  --help                    Display this help and exit"""

  DockerBootnode = "enode://f41f87f084ed7df4a9fd0833e395f49c89764462d3c4bc16d061a3ae5e3e34b79eb47d61c2f62db95ff32ae8e20965e25a3c9d9b8dbccaa8e8d77ac6fc8efc06@172.17.0.2:30301"
  # bootnodes taken from go-ethereum
  MainBootnodes* = [
    "enode://a979fb575495b8d6db44f750317d0f4622bf4c2aa3365d6af7c284339968eef29b69ad0dce72a4d8db5ebb4968de0e3bec910127f134779fbcb0cb6d3331163c@52.16.188.185:30303",
    "enode://3f1d12044546b76342d59d4a05532c14b85aa669704bfe1f864fe079415aa2c02d743e03218e57a33fb94523adb54032871a6c51b2cc5514cb7c7e35b3ed0a99@13.93.211.84:30303",
    "enode://78de8a0916848093c73790ead81d1928bec737d565119932b98c6b100d944b7a95e94f847f689fc723399d2e31129d182f7ef3863f2b4c820abbf3ab2722344d@191.235.84.50:30303",
    "enode://158f8aab45f6d19c6cbf4a089c2670541a8da11978a2f90dbf6a502a4a3bab80d288afdbeb7ec0ef6d92de563767f3b1ea9e8e334ca711e9f8e2df5a0385e8e6@13.75.154.138:30303",
    "enode://1118980bf48b0a3640bdba04e0fe78b1add18e1cd99bf22d53daac1fd9972ad650df52176e7c7d89d1114cfef2bc23a2959aa54998a46afcf7d91809f0855082@52.74.57.123:30303",
    "enode://979b7fa28feeb35a4741660a16076f1943202cb72b6af70d327f053e248bab9ba81760f39d0701ef1d8f89cc1fbd2cacba0710a12cd5314d5e0c9021aa3637f9@5.1.83.226:30303",
  ]
  # Whisper nodes taken from:
  # https://github.com/status-im/status-react/blob/80aa0e92864c638777a45c3f2aeb66c3ae7c0b2e/resources/config/fleets.json
  # These are probably not on the main network?
  WhisperNodes = [
    "enode://66ba15600cda86009689354c3a77bdf1a97f4f4fb3ab50ffe34dbc904fac561040496828397be18d9744c75881ffc6ac53729ddbd2cdbdadc5f45c400e2622f7@206.189.243.176:30305",
    "enode://0440117a5bc67c2908fad94ba29c7b7f2c1536e96a9df950f3265a9566bf3a7306ea8ab5a1f9794a0a641dcb1e4951ce7c093c61c0d255f4ed5d2ed02c8fce23@35.224.15.65:30305",
    "enode://a80eb084f6bf3f98bf6a492fd6ba3db636986b17643695f67f543115d93d69920fb72e349e0c617a01544764f09375bb85f452b9c750a892d01d0e627d9c251e@47.89.16.125:30305",
    "enode://4ea35352702027984a13274f241a56a47854a7fd4b3ba674a596cff917d3c825506431cf149f9f2312a293bb7c2b1cca55db742027090916d01529fe0729643b@206.189.243.178:30305",
    "enode://552942cc4858073102a6bcd0df9fe4de6d9fc52ddf7363e8e0746eba21b0f98fb37e8270bc629f72cfe29e0b3522afaf51e309a05998736e2c0dad5288991148@130.211.215.133:30305",
    "enode://aa97756bc147d74be6d07adfc465266e17756339d3d18591f4be9d1b2e80b86baf314aed79adbe8142bcb42bc7bc40e83ee3bbd0b82548e595bf855d548906a1@47.52.188.241:30305",
    "enode://ce559a37a9c344d7109bd4907802dd690008381d51f658c43056ec36ac043338bd92f1ac6043e645b64953b06f27202d679756a9c7cf62fdefa01b2e6ac5098e@206.189.243.179:30305",
    "enode://b33dc678589931713a085d29f9dc0efee1783dacce1d13696eb5d3a546293198470d97822c40b187336062b39fd3464e9807858109752767d486ea699a6ab3de@35.193.151.184:30305",
    "enode://f34451823b173dc5f2ac0eec1668fdb13dba9452b174249a7e0272d6dce16fb811a01e623300d1b7a67c240ae052a462bff3f60e4a05e4c4bd23cc27dea57051@47.52.173.66:30305",
    "enode://4e0a8db9b73403c9339a2077e911851750fc955db1fc1e09f81a4a56725946884dd5e4d11258eac961f9078a393c45bcab78dd0e3bc74e37ce773b3471d2e29c@206.189.243.171:30305",
    "enode://eb4cc33c1948b1f4b9cb8157757645d78acd731cc8f9468ad91cef8a7023e9c9c62b91ddab107043aabc483742ac15cb4372107b23962d3bfa617b05583f2260@146.148.66.209:30305",
    "enode://7c80e37f324bbc767d890e6381854ef9985d33940285413311e8b5927bf47702afa40cd5d34be9aa6183ac467009b9545e24b0d0bc54ef2b773547bb8c274192@47.91.155.62:30305",
    "enode://a8bddfa24e1e92a82609b390766faa56cf7a5eef85b22a2b51e79b333c8aaeec84f7b4267e432edd1cf45b63a3ad0fc7d6c3a16f046aa6bc07ebe50e80b63b8c@206.189.243.172:30305",
    "enode://c7e00e5a333527c009a9b8f75659d9e40af8d8d896ebaa5dbdd46f2c58fc010e4583813bc7fc6da98fcf4f9ca7687d37ced8390330ef570d30b5793692875083@35.192.123.253:30305",
    "enode://4b2530d045b1d9e0e45afa7c008292744fe77675462090b4001f85faf03b87aa79259c8a3d6d64f815520ac76944e795cbf32ff9e2ce9ba38f57af00d1cc0568@47.90.29.122:30305",
    "enode://887cbd92d95afc2c5f1e227356314a53d3d18855880ac0509e0c0870362aee03939d4074e6ad31365915af41d34320b5094bfcc12a67c381788cd7298d06c875@206.189.243.177:30305",
    "enode://2af8f4f7a0b5aabaf49eb72b9b59474b1b4a576f99a869e00f8455928fa242725864c86bdff95638a8b17657040b21771a7588d18b0f351377875f5b46426594@35.232.187.4:30305",
    "enode://76ee16566fb45ca7644c8dec7ac74cadba3bfa0b92c566ad07bcb73298b0ffe1315fd787e1f829e90dba5cd3f4e0916e069f14e50e9cbec148bead397ac8122d@47.91.226.75:30305",
    "enode://2b01955d7e11e29dce07343b456e4e96c081760022d1652b1c4b641eaf320e3747871870fa682e9e9cfb85b819ce94ed2fee1ac458904d54fd0b97d33ba2c4a4@206.189.240.70:30305",
    "enode://19872f94b1e776da3a13e25afa71b47dfa99e658afd6427ea8d6e03c22a99f13590205a8826443e95a37eee1d815fc433af7a8ca9a8d0df7943d1f55684045b7@35.238.60.236:30305"
  ]

type
  ShhConfig* = object
    listeningPort*: int
    post*: bool
    watch*: bool
    main*: bool
    local*: bool

proc processArguments*(): ShhConfig =
  var opt = initOptParser()
  var length = 0
  for kind, key, value in opt.getopt():
    case kind
    of cmdArgument:
      echo key
    of cmdLongOption, cmdShortOption:
      inc(length)
      case key.toLowerAscii()
        of "help", "h": quit(Usage, QuitSuccess)
        of "port", "p":
          result.listeningPort = value.parseInt
        of "post":
          result.post = true
        of "watch":
          result.watch = true
        of "mainnet":
          result.main = true
        of "local":
          result.local = true
        else: quit(Usage)
    of cmdEnd:
      quit(Usage)

let config = processArguments()

var port: Port
var address: Address
var netId: uint

# config
if config.listeningPort != 0:
  port = Port(config.listeningPort)
else:
  port = Port(DefaultListeningPort)
if config.local:
  address = Address(udpPort: port, tcpPort: port, ip: parseIpAddress("127.0.0.1"))
else:
  address = Address(udpPort: port, tcpPort: port, ip: parseIpAddress("0.0.0.0"))
if config.main:
  netId = 1
else:
  netId = 15

let keys = newKeyPair()
var node = newEthereumNode(keys, address, netId, nil, addAllCapabilities = false)
node.addCapability Whisper

# lets prepare some prearranged keypairs
let encPrivateKey = initPrivateKey("5dc5381cae54ba3174dc0d46040fe11614d0cc94d41185922585198b4fcef9d3")
let encPublicKey = encPrivateKey.getPublicKey()
let signPrivateKey = initPrivateKey("365bda0757d22212b04fada4b9222f8c3da59b49398fa04cf612481cd893b0a3")
let signPublicKey = signPrivateKey.getPublicKey()
var symKey: SymKey
# To test with geth: all 0's key is invalid in geth console
symKey[31] = 1
let topic = [byte 0x12, 0, 0, 0]

if config.main:
  var bootnodes: seq[ENode] = @[]
  for nodeId in MainBootnodes:
    var bootnode: ENode
    discard initENode(nodeId, bootnode)
    bootnodes.add(bootnode)

  asyncCheck node.connectToNetwork(bootnodes, true, true)
  # main network has mostly non SHH nodes, so we connect directly to SHH nodes
  for nodeId in WhisperNodes:
    var whisperENode: ENode
    discard initENode(nodeId, whisperENode)
    var whisperNode = newNode(whisperENode)
    asyncCheck node.peerPool.connectToNode(whisperNode)
else:
  var bootENode: ENode
  discard initENode(DockerBootNode, bootENode)
  waitFor node.connectToNetwork(@[bootENode], true, true)

if config.watch:
  proc handler(msg: ReceivedMessage) =
    echo msg.decoded.payload.repr

  # filter encrypted asym
  discard node.subscribeFilter(newFilter(privateKey = some(encPrivateKey),
                                         topics = @[topic]),
                               handler)
  # filter encrypted asym + signed
  discard node.subscribeFilter(newFilter(some(signPublicKey),
                                         privateKey = some(encPrivateKey),
                                         topics = @[topic]),
                               handler)
  # filter encrypted sym
  discard node.subscribeFilter(newFilter(symKey = some(symKey),
                                         topics = @[topic]),
                               handler)
  # filter encrypted sym + signed
  discard node.subscribeFilter(newFilter(some(signPublicKey),
                                         symKey = some(symKey),
                                         topics = @[topic]),
                               handler)

if config.post:
  # encrypted asym
  discard node.postMessage(some(encPublicKey), ttl = 5, topic = topic,
                           payload = repeat(byte 65, 10))
  poll()
  # # encrypted asym + signed
  discard node.postMessage(some(encPublicKey), src = some(signPrivateKey),
                           ttl = 5, topic = topic, payload = repeat(byte 66, 10))
  poll()
  # # encrypted sym
  discard node.postMessage(symKey = some(symKey), ttl = 5, topic = topic,
                           payload = repeat(byte 67, 10))
  poll()
  # # encrypted sym + signed
  discard node.postMessage(symKey = some(symKey), src = some(signPrivateKey),
                           ttl = 5, topic = topic, payload = repeat(byte 68, 10))

while true:
  poll()
