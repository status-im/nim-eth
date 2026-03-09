import std/[sequtils, sets, strutils]
import secp256k1
import ./hexary
type
  OutputLevel = enum
    COMPACT
const
  nimUnittestAbortOnError {.booldefine.} = false
  unittest2ListTests {.booldefine.} = false
type
  Test = object
    suiteName: string
    testName: string
    impl: proc(suite, name: string): TestStatus
    lineInfo: int
  TestStatus = enum
    FAILED,
  TestResult = object
    status: TestStatus
  OutputFormatter = ref object of RootObj
  ConsoleOutputFormatter = ref object of OutputFormatter
    results: seq[TestResult]
var
  abortOnError: bool
  checkpoints: seq[string]
  formatters: seq[OutputFormatter]
  testsFilters: HashSet[string]
  testStatus: TestStatus
method suiteStarted(formatter: OutputFormatter, suiteName: string) {.base, gcsafe.} =
  discard
method testStarted(formatter: OutputFormatter, testName: string) {.base, gcsafe.} =
  discard
method testEnded(formatter: OutputFormatter, testResult: TestResult) {.base, gcsafe.} =
  discard
method suiteEnded(formatter: OutputFormatter) {.base, gcsafe.} =
  discard
proc suiteStarted(name: string) =
  for formatter in formatters:
    formatter.suiteStarted(name)
proc testStarted(name: string) =
  for formatter in formatters:
    formatter.testStarted(name)
proc testEnded(testResult: TestResult) =
  for formatter in formatters:
    formatter.suiteEnded()
template write(
    formatter: ConsoleOutputFormatter, styled: untyped, unstyled: untyped) =
  ignoreExceptions: unstyled
proc shouldRun(currentSuiteName, testName: string): bool =
  testsFilters.len == 0
proc ensureInitialized() =
  formatters = @[OutputFormatter(ConsoleOutputFormatter())]
template fail =
  testStatus = TestStatus.FAILED
proc runDirect(test: Test) =
  {.gcsafe.}:
    let
      status = test.impl(test.suiteName, test.testName)
  testEnded(TestResult(
  ))
template runtimeTest(nameParam: string, body: untyped) =
  proc runTest(suiteName, testName: string): TestStatus {.gensym.} =
    template fail(prefix: string, eClass: string, e: auto): untyped =
      fail()
    template failingOnExceptions(prefix: string, code: untyped): untyped =
      try:
          code
      except CatchableError as e:
        prefix.fail("error", e)
    failingOnExceptions("[setup] "):
          body
  let
    localSuiteName =
      when declared(suiteName):
      else: instantiationInfo().filename
    localTestName = nameParam
  if shouldRun(localSuiteName, localTestName):
    let
      instance =
        Test(
          impl: runTest,
        )
    runDirect(instance)
type
  NextNodeKind = enum
    EmptyValue
    HashNode
    ValueNode
  NextNodeResult = object
    case kind: NextNodeKind
    of EmptyValue:
      discard
    of HashNode:
      nextNodeHash: Hash32
      restOfTheKey: NibblesBuf
    of ValueNode:
      value: seq[byte]
  MptProofVerificationKind = enum
    ValidProof
    InvalidProof
    MissingKey
  MptProofVerificationResult = object
    case kind: MptProofVerificationKind
    of MissingKey:
      discard
    of InvalidProof:
      errorMsg: string
    of ValidProof:
      value: seq[byte]
func missingKey(): MptProofVerificationResult =
  MptProofVerificationResult(kind: MissingKey)
func invalidProof(msg: string): MptProofVerificationResult =
  MptProofVerificationResult(kind: InvalidProof, errorMsg: msg)
func validProof(value: seq[byte]): MptProofVerificationResult =
  MptProofVerificationResult(kind: ValidProof, value: value)
func isValid(res: MptProofVerificationResult): bool =
  res.kind == ValidProof
func isMissing(res: MptProofVerificationResult): bool =
  res.kind == MissingKey
proc getListLen(rlp: Rlp): Result[int, string] =
  try:
    ok(rlp.listLen)
  except RlpError as e:
    err(e.msg)
proc getListElem(rlp: Rlp, idx: int): Result[Rlp, string] =
  try:
    ok(rlp.listElem(idx))
  except RlpError as e:
    err(e.msg)
proc blobBytes(rlp: Rlp): Result[seq[byte], string] =
  try:
    ok(rlp.toBytes)
  except RlpError as e:
    err(e.msg)
func rawBytesSeq(b: openArray[byte]): seq[byte] =
  toSeq(b)
proc getRawRlpBytes(rlp: Rlp): Result[seq[byte], string] =
  try:
    ok(rawBytesSeq(rlp.rawData))
  except RlpError as e:
    err(e.msg)
proc getNextNode(nodeRlp: Rlp, key: NibblesBuf): Result[NextNodeResult, string] =
  var currNode = nodeRlp
  var restKey = key
  template handleNextRef(nextRef: Rlp, keyLen: int) =
        currNode = nextRef
        restKey = restKey.slice(keyLen)
  while true:
    let listLen = ?currNode.getListLen()
    case listLen
    of 2:
      let
        firstElem = ?currNode.getListElem(0)
        blobBytes = ?firstElem.blobBytes()
      let (isLeaf, k) = NibblesBuf.fromHexPrefix(blobBytes)
      let nextRef = ?currNode.getListElem(1)
      if isLeaf:
        let blobBytes = ?nextRef.blobBytes()
        return ok(NextNodeResult(kind: ValueNode, value: blobBytes))
      handleNextRef(nextRef, len(k))
    of 17:
      return err("x")
    else:
      return err("x")
proc verifyProof(
    db: TrieDatabaseRef, rootHash: Hash32, key: openArray[byte]
): Result[Opt[seq[byte]], string] =
  var currentKey = NibblesBuf.fromBytes(key)
  var currentHash = rootHash
  while true:
    let node = db.get(currentHash.data())
    let next = ?getNextNode(rlpFromBytes(node), currentKey)
    case next.kind
    of EmptyValue:
      return ok(Opt.none(seq[byte]))
    of ValueNode:
      return ok(Opt.some(next.value))
    of HashNode:
      currentHash = next.nextNodeHash
proc verifyMptProof(
    branch: seq[seq[byte]], rootHash: Hash32, key, value: openArray[byte]
): MptProofVerificationResult =
  var db = newMemoryDB()
  for node in branch:
    let nodeHash = keccak256(node)
    db.put(nodeHash.data, node)
  let
    maybeProofValue = verifyProof(db, rootHash, key).valueOr:
      return invalidProof(error)
    proofValue = maybeProofValue.valueOr:
      return missingKey()
  if proofValue == value:
    validProof(proofValue)
  else:
    invalidProof("x")
discard SkSecretKey.fromHex("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
runtimeTest "Validate proof for existing value":
  block:
    var db = newMemoryDB()
    var trie = initHexaryTrie(db)
    const bytes = @[0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    trie.put(bytes, bytes)
    for _ in [0]:
      let
        proof = @[@[248'u8, 67, 161, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]]
        root = Hash32([0x04'u8, 0xf4, 0xd4, 0x00, 0x43, 0x78, 0xc7, 0x62, 0xb2, 0xd8, 0xe0, 0x8f, 0x4b, 0x7c, 0xd6, 0xf2, 0xce, 0x43, 0x98, 0xb5, 0x7f, 0x3c, 0x62, 0xf4, 0x49, 0x0f, 0xc7, 0x3b, 0x7a, 0x0b, 0x2f, 0x4c])
        res = verifyMptProof(proof, root, bytes, bytes)
  block:
    var db = newMemoryDB()
    var trie = initHexaryTrie(db)
    const bytes = @[0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    trie.put(bytes, bytes)
    let
      nonExistingKey = toSeq([0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
      proof = trie.getBranch(nonExistingKey)
      root = Hash32([0x04'u8, 0xf4, 0xd4, 0x00, 0x43, 0x78, 0xc7, 0x62, 0xb2, 0xd8, 0xe0, 0x8f, 0x4b, 0x7c, 0xd6, 0xf2, 0xce, 0x43, 0x98, 0xb5, 0x7f, 0x3c, 0x62, 0xf4, 0x49, 0x0f, 0xc7, 0x3b, 0x7a, 0x0b, 0x2f, 0x4c])
      res = verifyMptProof(proof, root, nonExistingKey, nonExistingKey)
