import 
  ../../../eth/[rlp, common],
  times,
  std/[os, strutils],
  stew/io2,
  results

type
  Timeval {.importc: "timeval", header:"<sys/time.h>", bycopy.} = object
  
  Rusage* {.importc: "struct rusage", header:"<sys/resource.h>", bycopy.} = object
    ru_utime {.importc.}: Timeval
    ru_stime {.importc.}: Timeval
    ru_maxrss* {.importc.}: int32  # Maximum resident set size
    # ...
    ru_minflt* {.importc.}: int32  # page reclaims (soft page faults)
  
  RusageWho* {.size: sizeof(cint).} = enum
    RusageChildren = -1
    RusageSelf = 0
    RusageThread = 1

when defined(debug):
  var H_RUSAGE_SELF{.importc, header:"<sys/resource.h".}: cint
  var H_RUSAGE_CHILDREN{.importc, header:"<sys/resource.h".}: cint
  var H_RUSAGE_THREAD{.importc, header:"<sys/resource.h".}: cint
  assert H_RUSAGE_SELF == ord(RusageSelf)
  assert H_RUSAGE_CHILDREN = ord(RusageChildren)
  assert H_RUSAGE_THREAD = ord(RusageThread)

proc getrusage*(who: RusageWho, usage: var Rusage) {.importc, header: "sys/resource.h".}

const 
  accesses  = @[AccessPair(
    address: address"0x0000000000000000000000000000000000000001", 
    storageKeys: @[default(Bytes32)]
  )]

  tx = Transaction( 
    txType: TxLegacy, 
    chainId: 7.ChainId, 
    nonce: 11253.AccountNonce, 
    gasPrice: 9.GasInt, 
    maxPriorityFeePerGas: 0.GasInt, 
    maxFeePerGas: 0.GasInt, 
    gasLimit: 88920.GasInt, 
    payload: @[99, 0, 0, 0, 25, 96, 1, 1, 56, 3, 128, 99, 0, 0, 0, 25, 96, 1, 1, 96, 0, 57, 96, 0, 243, 91, 78, 30, 176, 85, 200, 234, 14, 45, 97, 73, 65, 149, 199, 11, 118, 202, 83, 30, 211, 109, 119, 168, 184, 89, 6, 38, 132, 53, 2, 237, 54, 131, 30, 141, 225, 155, 174, 92, 96, 211, 133, 53, 218, 245, 132, 17, 173, 79, 95, 241, 197, 214, 244, 196, 37, 88, 27, 34, 51, 69, 116, 64, 170, 77, 95, 191, 152, 7, 214, 85, 249, 244, 167, 67, 76, 137, 136, 37, 169, 40, 20, 131, 165, 153, 120, 158, 20, 26, 114, 99, 129, 254, 172, 229, 99, 18, 178, 251, 40, 126, 210, 155, 108, 238, 127, 2, 156, 67, 61, 199, 191, 71, 215, 72, 23, 173, 131, 213, 35, 87, 54, 248, 41, 221, 119, 31, 223, 144], 
    accessList: @[], 
    maxFeePerBlobGas: 0.u256, 
    versionedHashes: @[], 
    authorizationList: @[], 
    V: uint64(49), 
    R: 2812423844.u256, 
    S: 532553168.u256
  )

  header = Header(
    parentHash: Hash32.fromHex("0x4d24f4dddde8ab09ea900bc87492f74e44e1c3982042d0fd01673a98e72c14a6"), 
    ommersHash: Hash32.fromHex("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"), 
    coinbase: Address.fromHex("0x0000000000000000000000000000000000000000"), 
    stateRoot: Root.fromHex("0xa06c17a5ebaeacef3b760293e8f2092e775448c038aa7361350cde9f27e6b218"), 
    transactionsRoot: Root.fromHex("0x773faa6ccc82788a4392df241b7c6e7175fd77648fed2aaad583a528293a80bc"), 
    receiptsRoot: Root.fromHex("0x8ccc9b260110dad8161d01e72913cd27baab66809aa106a4c28a7c7a3a418b65"), 
    difficulty: 131072.u256, 
    number: 1024.BlockNumber, 
    gasLimit: 3141592.GasInt, 
    gasUsed: 891237.GasInt, 
    timestamp: EthTime(15748660), 
    extraData: @[], 
    mixHash: Bytes32.fromHex("0x378c37bd4d8692035f9d03a619d7c44a579d3b1c1c52db3096bc92a71b74aeb5"), 
    nonce: Bytes8.fromHex("0x4ea813c0c15b4215"), 
    baseFeePerGas: Opt.some(9.u256), 
  )

  blk = EthBlock(
    header: header,
    transactions: @[
      tx, tx, tx, tx,
      tx, tx, tx, tx
    ],
    uncles: @[],
  )
  
  blk80 = EthBlock(
    header: header, 
    transactions: @[
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx], 
    uncles: @[], 
  )

  blk320 = EthBlock(
    header: header, 
    transactions: @[
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx], 
    uncles: @[], 
  )
  
  blk640 = EthBlock(
    header: header, 
    transactions: @[
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx], 
    uncles: @[], 
  )
  
  blk1280 = EthBlock(
    header: header, 
    transactions: @[
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx,
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx, 
      tx, tx, tx, tx, tx, tx, tx, tx], 
    uncles: @[], 
  )

proc encodeOnePass[T](v: T): seq[byte] =
  var writer = initRlpWriter()

  writer.append(v)
  move(writer.finish)

proc encodeAndHash[T](v: T): Hash32 =
  keccak256(encodeOnePass(v))

# source: https://forum.nim-lang.org/t/7238
{.push checks: off.}
template benchmark(msg: string, code: untyped) =
  when not defined(windows):
    var ru: Rusage
    getrusage(RusageSelf, ru)
    var
      rss = ru.ru_maxrss
      flt = ru.ru_minflt

  when not defined(windows):
    let start = cpuTime()

  code

  when not defined(windows):
    let stop = cpuTime()

  when not defined(windows):
    getrusage(RusageSelf, ru)
    rss = ru.ru_maxrss - rss
    flt = ru.ru_minflt - flt

  echo "Benchmark: " & msg
  when not defined(windows):
    echo "Time(s)              ", stop - start
    echo "Runtime RSS (KB):     ", rss
    echo "# of page faults:     ", flt
{.pop.}

when defined(opt):
  when defined(hash):
    when defined(tx):
      benchmark "encodeHash single transactions":
        let bytes1 = rlp.encodeHash(tx)
    elif defined(header):
      benchmark "encodeHash header":
        let bytes1 = rlp.encodeHash(header)
    elif defined(blk):
      benchmark "encodeHash block with 8 transactions":
        let bytes2 = rlp.encodeHash(blk)
    elif defined(blk80):
      benchmark "encodeHash block with 80 transactions":
        let bytes2 = rlp.encodeHash(blk80)
    elif defined(blk320):
      benchmark "encodeHash block with 320 transactions":
        let bytes2 = rlp.encodeHash(blk320)
    elif defined(blk640):
      benchmark "encodeHash block with 640 transactions":
        let bytes2 = rlp.encodeHash(blk640)
    elif defined(blk1280):
      benchmark "encodeHash block with 1280 transactions":
        let bytes2 = rlp.encodeHash(blk1280)
  else:
    when defined(tx):
      benchmark "encode single transactions":
        let bytes1 = rlp.encode(tx)
    elif defined(header):
      benchmark "encode header":
        let bytes1 = rlp.encode(header)
    elif defined(blk):
      benchmark "encode block with 8 transactions":
        let bytes2 = rlp.encode(blk)
    elif defined(blk80):
      benchmark "encode block with 80 transactions":
        let bytes2 = rlp.encode(blk80)
    elif defined(blk320):
      benchmark "encode block with 320 transactions":
        let bytes2 = rlp.encode(blk320)
    elif defined(blk640):
      benchmark "encode block with 640 transactions":
        let bytes2 = rlp.encode(blk640)
    elif defined(blk1280):
      benchmark "encode block with 1280 transactions":
        let bytes2 = rlp.encode(blk1280)
else:
  when defined(hash):
    when defined(tx):
      benchmark "encodeAndHash single transactions":
        let bytes1 = encodeAndHash(tx)
    elif defined(header):
      benchmark "encodeAndHash header":
        let bytes1 = encodeAndHash(header)
    elif defined(blk):
      benchmark "encodeAndHash block with 8 transactions":
        let bytes2 = encodeAndHash(blk)
    elif defined(blk80):
      benchmark "encodeAndHash block with 80 transactions":
        let bytes2 = encodeAndHash(blk80)
    elif defined(blk320):
      benchmark "encodeAndHash block with 320 transactions":
        let bytes2 = encodeAndHash(blk320)
    elif defined(blk640):
      benchmark "encodeAndHash block with 640 transactions":
        let bytes2 = encodeAndHash(blk640)
    elif defined(blk1280):
      benchmark "encodeAndHash block with 1280 transactions":
        let bytes2 = encodeAndHash(blk1280)
  else:
    when defined(tx):
      benchmark "encodeOnePass single transactions":
        let bytes1 = encodeOnePass(tx)
    elif defined(header):
      benchmark "encodeOnePass header":
        let bytes1 = encodeOnePass(header)
    elif defined(blk):
      benchmark "encodeOnePass block with 8 transactions":
        let bytes2 = encodeOnePass(blk)
    elif defined(blk80):
      benchmark "encodeOnePass block with 80 transactions":
        let bytes2 = encodeOnePass(blk80)
    elif defined(blk320):
      benchmark "encodeOnePass block with 320 transactions":
        let bytes2 = encodeOnePass(blk320)
    elif defined(blk640):
      benchmark "encodeOnePass block with 640 transactions":
        let bytes2 = encodeOnePass(blk640)
    elif defined(blk1280):
      benchmark "encodeOnePass block with 1280 transactions":
        let bytes2 = encodeOnePass(blk1280)
