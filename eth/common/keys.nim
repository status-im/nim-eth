{.push raises: [].}


import std/[
  sequtils, sets, strutils, streams, times, monotimes]

when declared(stdout):
  import std/os

type
  OutputLevel = enum  ## The output verbosity of the tests.
    VERBOSE,     ## Print as much as possible.
    COMPACT      ## Print failures and compact success information
    FAILURES,    ## Print only failures
    NONE         ## Print nothing.

const
  outputLevelDefault = COMPACT
  nimUnittestOutputLevel {.strdefine.} = $outputLevelDefault
  nimUnittestColor {.strdefine.} = "auto" ## auto|on|off
  nimUnittestAbortOnError {.booldefine.} = false
  unittest2ListTests {.booldefine.} = false

import std/terminal

type
  Test = object
    suiteName: string
    testName: string
    impl: proc(suite, name: string): TestStatus
    lineInfo: int

  TestStatus = enum ## The status of a test when it is done.
    OK,
    FAILED,
    SKIPPED

  TestResult = object
    suiteName: string
    testName: string
    status: TestStatus
    output: string
    errors: string

  OutputFormatter = ref object of RootObj

  ConsoleOutputFormatter = ref object of OutputFormatter
    colorOutput: bool
    outputLevel: OutputLevel

    curSuiteName: string
    curSuite: int
    curTestName: string
    curTest: int

    statuses: array[TestStatus, int]

    totalDuration: Duration

    results: seq[TestResult]

    failures: seq[TestResult]

    errors: string

  JUnitTest = object
    name: string
    result: TestResult
    error: (seq[string], string)
    failures: seq[seq[string]]

  JUnitSuite = object
    name: string
    tests: seq[JUnitTest]

  JUnitOutputFormatter = ref object of OutputFormatter
    stream: Stream
    defaultSuite: JUnitSuite
    suites: seq[JUnitSuite]
    currentSuite: int


var
  abortOnError: bool

  checkpoints: seq[string]
  formatters: seq[OutputFormatter]
  testsFilters: HashSet[string]

  currentSuite: string
  testStatus: TestStatus

abortOnError = nimUnittestAbortOnError

method suiteStarted(formatter: OutputFormatter, suiteName: string) {.base, gcsafe.} =
  discard
method testStarted(formatter: OutputFormatter, testName: string) {.base, gcsafe.} =
  discard
method failureOccurred(formatter: OutputFormatter, checkpoints: seq[string],
    stackTrace: string) {.base, gcsafe.} =
  discard
method testEnded(formatter: OutputFormatter, testResult: TestResult) {.base, gcsafe.} =
  discard
method suiteEnded(formatter: OutputFormatter) {.base, gcsafe.} =
  discard

method testRunEnded(formatter: OutputFormatter) {.base, gcsafe.} =
  discard

proc suiteStarted(name: string) =
  for formatter in formatters:
    formatter.suiteStarted(name)

proc testStarted(name: string) =
  for formatter in formatters:
    formatter.testStarted(name)

proc testEnded(testResult: TestResult) =
  for formatter in formatters:
    formatter.testEnded(testResult)

proc suiteEnded() =
  for formatter in formatters:
    formatter.suiteEnded()

proc newConsoleOutputFormatter(outputLevel: OutputLevel = outputLevelDefault,
                                colorOutput = true): ConsoleOutputFormatter =
  ConsoleOutputFormatter(
    outputLevel: outputLevel,
    colorOutput: colorOutput,
  )

proc defaultColorOutput(): bool =
  let color = nimUnittestColor
  case color
  of "auto":
    when declared(stdout): result = isatty(stdout)
    else: result = false
  of "on": result = true
  of "off": result = false
  else: raiseAssert "Unrecognised nimUnittestColor setting: " & color

  when declared(stdout):
    if existsEnv("NIMTEST_COLOR"):
      let colorEnv = getEnv("NIMTEST_COLOR")
      if colorEnv == "never":
        result = false
      elif colorEnv == "always":
        result = true
    elif existsEnv("NIMTEST_NO_COLOR"):
      result = false

proc defaultOutputLevel(): OutputLevel =
  when declared(stdout):
    const levelEnv = "UNITTEST2_OUTPUT_LVL"
    const nimtestEnv = "NIMTEST_OUTPUT_LVL"
    if existsEnv(levelEnv):
      try:
        parseEnum[OutputLevel](getEnv(levelEnv))
      except ValueError:
        echo "Cannot parse UNITTEST2_OUTPUT_LVL: ", getEnv(levelEnv)
        quit 1
    elif existsEnv(nimtestEnv):
      case toUpper(getEnv(nimtestEnv))
      of "PRINT_ALL": OutputLevel.VERBOSE
      of "PRINT_FAILURES": OutputLevel.FAILURES
      of "PRINT_NONE": OutputLevel.NONE
      else:
        echo "Cannot parse NIMTEST_OUTPUT_LVL: ", getEnv(nimtestEnv)
        quit 1
    else:
      const defaultLevel = static: nimUnittestOutputLevel.parseEnum[:OutputLevel]
      defaultLevel

proc defaultConsoleFormatter(): ConsoleOutputFormatter =
  newConsoleOutputFormatter(defaultOutputLevel(), defaultColorOutput())

const
  maxStatusLen = 7
  maxDurationLen = 6

func formatStatus(status: string): string =
  "[" & alignLeft(status, maxStatusLen) & "]"

template write(
    formatter: ConsoleOutputFormatter, styled: untyped, unstyled: untyped) =
  template ignoreExceptions(body: untyped) =
    try: body except CatchableError: discard

  if formatter.colorOutput:
    ignoreExceptions: styled
  else: ignoreExceptions: unstyled

method suiteStarted(formatter: ConsoleOutputFormatter, suiteName: string) =
  formatter.curSuiteName = suiteName
  formatter.curSuite += 1

  formatter.curTest.reset()

  if formatter.outputLevel in {OutputLevel.FAILURES, OutputLevel.NONE}:
    return

  let
    counter =
      if formatter.outputLevel == VERBOSE: formatStatus("Suite") & " " else: ""
    maxNameLen = 0
    eol = if formatter.outputLevel == VERBOSE: "\n" else: " "
  formatter.write do:
    stdout.styledWrite(styleBright, fgBlue, counter, alignLeft(suiteName, maxNameLen), eol)
  do:
    stdout.write(counter, alignLeft(suiteName, maxNameLen), eol)
  stdout.flushFile()

proc writeTestName(formatter: ConsoleOutputFormatter, testName: string) =
  formatter.write do:
    stdout.styledWrite fgBlue, testName
  do:
    stdout.write(testName)

method testStarted(formatter: ConsoleOutputFormatter, testName: string) =
  formatter.curTestName = testName
  formatter.curTest += 1

  if formatter.outputLevel != VERBOSE:
    return

  let
    counter = formatStatus("Test")

  formatter.write do:
    stdout.styledWrite "  ", fgBlue, alignLeft(counter, maxStatusLen + maxDurationLen + 7)
  do:
    stdout.write "  ", alignLeft(counter, maxStatusLen + maxDurationLen + 7)

  writeTestName(formatter, testName)
  echo ""

method failureOccurred(formatter: ConsoleOutputFormatter,
                        checkpoints: seq[string], stackTrace: string) = discard
proc color(status: TestStatus): ForegroundColor = discard
proc marker(status: TestStatus): string = discard
proc getAppFilename2(): string =
  try:
    getAppFilename()
  except OSError:
    ""

proc printFailureInfo(formatter: ConsoleOutputFormatter, testResult: TestResult) =
  echo repeat('=', testResult.testName.len)
  echo "  ", getAppFilename2(), " ", quoteShell(testResult.suiteName & "::" & testResult.testName)
  echo repeat('-', testResult.testName.len)

  if testResult.output.len > 0:
    echo testResult.output
  if testResult.errors.len > 0:
    echo testResult.errors

proc printTestResultStatus(formatter: ConsoleOutputFormatter, testResult: TestResult) = discard
method testEnded(formatter: ConsoleOutputFormatter, testResult: TestResult) =
  if formatter.outputLevel == NONE:
    return

  var testResult = testResult
  testResult.errors = move(formatter.errors)

  formatter.results.add(testResult)

  if formatter.outputLevel == VERBOSE and testResult.status == TestStatus.FAILED:
    formatter.failures.add testResult

  let
    marker = testResult.status.marker()
    color = testResult.status.color()
  formatter.write do:
      stdout.styledWrite styleBright, color, marker
  do:
    stdout.write marker
  stdout.flushFile()

method suiteEnded(formatter: ConsoleOutputFormatter) =
  if formatter.outputLevel == OutputLevel.NONE:
    return

  var failed = false
  if formatter.outputLevel notin {VERBOSE, FAILURES}:
    for testResult in formatter.results:
      if testResult.status == TestStatus.FAILED:
        failed = true
        formatter.printFailureInfo(testResult)
        formatter.printTestResultStatus(testResult)
        echo ""

  formatter.results.reset()

method testRunEnded(formatter: ConsoleOutputFormatter) = discard

template suite(formatter: JUnitOutputFormatter): untyped =
  if formatter.currentSuite == -1:
    addr formatter.defaultSuite
  else:
    addr formatter.suites[formatter.currentSuite]

method failureOccurred(formatter: JUnitOutputFormatter,
                        checkpoints: seq[string], stackTrace: string) =
  if stackTrace.len > 0:
    formatter.suite().tests[^1].error = (checkpoints, stackTrace)
  else:
    formatter.suite().tests[^1].failures.add(checkpoints)

proc glob(matcher, filter: string): bool =
  if filter.len == 0:
    return true

  if not filter.contains('*'):
    return matcher == filter

  let beforeAndAfter = filter.split('*', maxsplit=1)
  if beforeAndAfter.len == 1:
    return matcher.startsWith(beforeAndAfter[0])

  if matcher.len < filter.len - 1:
    return false  # "12345" should not match "123*345"

  return matcher.startsWith(beforeAndAfter[0]) and matcher.endsWith(
      beforeAndAfter[1])

proc matchFilter(suiteName, testName, filter: string): bool =
  if filter == "":
    return true
  if testName == filter:
    return true
  let suiteAndTestFilters = filter.split("::", maxsplit=1)

  if suiteAndTestFilters.len == 1:
    let testFilter = suiteAndTestFilters[0]
    return glob(testName, testFilter)

  return glob(suiteName, suiteAndTestFilters[0]) and
         glob(testName, suiteAndTestFilters[1])

proc shouldRun(currentSuiteName, testName: string): bool =
  when nimvm:
    true
  else:
    if testsFilters.len == 0:
      return true

    for f in testsFilters:
      if matchFilter(currentSuiteName, testName, f):
        return true

    return false

proc ensureInitialized() =
  formatters = @[OutputFormatter(defaultConsoleFormatter())]

ensureInitialized() # Run once!

template suite(nameParam: string, body: untyped) {.dirty.} =
  bind currentSuite, suiteStarted, suiteEnded

  block:
    template setup(setupBody: untyped) {.dirty, used.} =
      var testSetupIMPLFlag {.used.} = true
      template testSetupIMPL: untyped {.dirty.} = setupBody

    when nimvm:
      discard
    else:
      let suiteName {.inject.} = nameParam
      if currentSuite.len > 0:
        suiteEnded()
        currentSuite.reset()
      currentSuite = suiteName

      suiteStarted(suiteName)

    body

    when nimvm:
      discard
    else:
      suiteEnded()
      currentSuite.reset()

template fail =
  when nimvm:
    echo "Tests failed"
    quit 1
  else:
    testStatus = TestStatus.FAILED

    for formatter in formatters:
      let formatter = formatter # avoid lent iterator
      formatter.failureOccurred(checkpoints, "")

    if abortOnError: quit(1)

    checkpoints.reset()

proc runDirect(test: Test) =
  let startTime = getMonoTime()
  testStarted(test.testName)

  {.gcsafe.}:
    let
      status = test.impl(test.suiteName, test.testName)
      _ = getMonoTime() - startTime

  testEnded(TestResult(
    suiteName: test.suiteName,
    testName: test.testName,
    status: status,
  ))

template runtimeTest(nameParam: string, body: untyped) =
  bind runDirect, shouldRun, checkpoints

  proc runTest(suiteName, testName: string): TestStatus {.raises: [], gensym.} =
    testStatus = TestStatus.OK
    template testStatusIMPL: var TestStatus {.inject, used.} = testStatus
    let suiteName {.inject, used.} = suiteName
    let testName {.inject, used.} = testName

    template fail(prefix: string, eClass: string, e: auto): untyped =
      let eName {.used.} = "[" & $e.name & "]"
      var stackTrace {.inject, used.} = e.getStackTrace()
      fail()

    template failingOnExceptions(prefix: string, code: untyped): untyped =
      try:
        block:
          code
      except CatchableError as e:
        prefix.fail("error", e)

    failingOnExceptions("[setup] "):
      when declared(testSetupIMPLFlag): testSetupIMPL()
      defer: failingOnExceptions("[teardown] "):
        when declared(testTeardownIMPLFlag): testTeardownIMPL()
      failingOnExceptions(""):
        when not unittest2ListTests:
          body

    checkpoints = @[]

    testStatus

  let
    localSuiteName =
      when declared(suiteName):
        suiteName
      else: instantiationInfo().filename
    localTestName = nameParam
  if shouldRun(localSuiteName, localTestName):
    let
      instance =
        Test(
          testName: localTestName, 
          suiteName: localSuiteName, 
          impl: runTest,
          lineInfo: instantiationInfo().line,
        )
    runDirect(instance)

{.pop.} # raises: []

iterator unittest2EvalOnceIter[T](x: T): auto =
  yield x
template unittest2EvalOnce(name: untyped, param: typed, blk: untyped) =
  for name in unittest2EvalOnceIter(param):
    blk

import
  secp256k1,
  "."/hashes,
  std/net,
  ../trie/[hexary, db, hexary_proof_verification]

discard SkSecretKey.fromHex("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")

suite "MPT trie proof verification":
  runtimeTest "Validate proof for existing value":
    block:
      var db = newMemoryDB()
      var trie = initHexaryTrie(db)

      const bytes = @[0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
      trie.put(bytes, bytes)

      for _ in [0]:
        let
          proof = @[@[248'u8, 67, 161, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]] # trie.getBranch(bytes)
          root = Hash32([0x04'u8, 0xf4, 0xd4, 0x00, 0x43, 0x78, 0xc7, 0x62, 0xb2, 0xd8, 0xe0, 0x8f, 0x4b, 0x7c, 0xd6, 0xf2, 0xce, 0x43, 0x98, 0xb5, 0x7f, 0x3c, 0x62, 0xf4, 0x49, 0x0f, 0xc7, 0x3b, 0x7a, 0x0b, 0x2f, 0x4c]) # trie.rootHash()
          res = verifyMptProof(proof, root, bytes, bytes)

        doAssert res.isValid()
        unittest2EvalOnce(foobar, res.value) do:
          block:
            if not(foobar == bytes):
              discard

    block:
      var db = newMemoryDB()
      var trie = initHexaryTrie(db)

      const bytes = @[0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
      trie.put(bytes, bytes)

      let
        nonExistingKey = toSeq([0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
        proof = trie.getBranch(nonExistingKey)
        # proof = @[@[248'u8, 67, 161, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]] # trie.getBranch(nonExistingKey)
        root = Hash32([0x04'u8, 0xf4, 0xd4, 0x00, 0x43, 0x78, 0xc7, 0x62, 0xb2, 0xd8, 0xe0, 0x8f, 0x4b, 0x7c, 0xd6, 0xf2, 0xce, 0x43, 0x98, 0xb5, 0x7f, 0x3c, 0x62, 0xf4, 0x49, 0x0f, 0xc7, 0x3b, 0x7a, 0x0b, 0x2f, 0x4c]) # trie.rootHash()
        res = verifyMptProof(proof, root, nonExistingKey, nonExistingKey)

      doAssert res.isMissing()
