# proof verification
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[tables, options, sequtils],
  stew/results,
  nimcrypto/[keccak, hash],
  ".."/rlp,
  "."/[trie_defs, nibbles, db]

type
  NextNodeKind = enum
    EmptyValue, HashNode, ValueNode

  NextNodeResult = object
    case kind: NextNodeKind
    of EmptyValue:
      discard
    of HashNode:
      nextNodeHash: seq[byte]
      restOfTheKey: NibblesSeq
    of ValueNode:
      value: seq[byte]

  MptProofVerificationKind* = enum
    ValidProof, InvalidProof, MissingKey

  MptProofVerificationResult* = object
    case kind*: MptProofVerificationKind
    of MissingKey:
      discard
    of InvalidProof:
      errorMsg*: string
    of ValidProof:
      value*: seq[byte]

func missingKey(): MptProofVerificationResult =
  return MptProofVerificationResult(kind: MissingKey)

func invalidProof(msg: string): MptProofVerificationResult =
  return MptProofVerificationResult(kind: InvalidProof, errorMsg: msg)

func validProof(value: seq[byte]): MptProofVerificationResult =
  return MptProofVerificationResult(kind: ValidProof, value: value)

func isValid*(res: MptProofVerificationResult): bool =
  return res.kind == ValidProof

func isMissing*(res: MptProofVerificationResult): bool =
  return res.kind == MissingKey

proc getListLen(rlp: Rlp): Result[int, string] =
  try:
    return ok(rlp.listLen)
  except RlpError as e:
    return err(e.msg)

proc getListElem(rlp: Rlp, idx: int): Result[Rlp, string] =
  if not rlp.isList:
    return err("rlp element is not a list")

  try:
    return ok(rlp.listElem(idx))
  except RlpError as e:
    return err(e.msg)

proc blobBytes(rlp: Rlp): Result[seq[byte], string] =
  try:
    return ok(rlp.toBytes)
  except RlpError as e:
    return err(e.msg)

func rawBytesSeq(b: openArray[byte]): seq[byte] =
  toSeq(b)

proc getRawRlpBytes(rlp: Rlp): Result[seq[byte], string] =
  try :
    return ok(rawBytesSeq(rlp.rawData))
  except RlpError as e:
    return err(e.msg)

proc getNextNode(nodeRlp: Rlp, key: NibblesSeq): Result[NextNodeResult, string] =
  var currNode = nodeRlp
  var restKey = key

  template handleNextRef(nextRef: Rlp, keyLen: int) =
    if not nextRef.hasData:
      return err("invalid reference")

    if nextRef.isList:
      let rawBytes = ? nextRef.getRawRlpBytes()
      if len(rawBytes) > 32:
        return err("Embedded node longer than 32 bytes")
      else:
        currNode = nextRef
        restKey = restKey.slice(keyLen)
    else:
      let nodeBytes = ? nextRef.blobBytes()
      if len(nodeBytes) == 32:
        return ok(
          NextNodeResult(
            kind: HashNode,
            nextNodeHash: nodeBytes,
            restOfTheKey: restKey.slice(keyLen)
          )
        )
      elif len(nodeBytes) == 0:
        return ok(NextNodeResult(kind: EmptyValue))
      else:
        return err("reference rlp blob should have 0 or 32 bytes")

  while true:
    let listLen = ? currNode.getListLen()

    case listLen
    of 2:
      let
        firstElem = ? currNode.getListElem(0)
        blobBytes = ? firstElem.blobBytes()

      let (isLeaf, k) = hexPrefixDecode blobBytes

      # Paths have diverged, return empty result
      if len(restKey) < len(k) or k != restKey.slice(0, len(k)):
        return ok(NextNodeResult(kind: EmptyValue))

      let nextRef = ? currNode.getListElem(1)

      if isLeaf:
        let blobBytes = ? nextRef.blobBytes()
        return ok(NextNodeResult(kind: ValueNode, value: blobBytes))

      handleNextRef(nextRef, len(k))
    of 17:
      if len(restKey) == 0:
        let value = ? currNode.getListElem(16)

        if not value.hasData():
          return err("expected branch terminator")

        if value.isList():
          return err("branch value cannot be list")

        if value.isEmpty():
          return ok(NextNodeResult(kind: EmptyValue))
        else:
          let bytes = ? value.blobBytes()
          return ok(NextNodeResult(kind: ValueNode, value: bytes))
      else:
        let nextRef = ? currNode.getListElem(restKey[0].int)

        handleNextRef(nextRef, 1)
    else:
      return err("Invalid list node ")

proc verifyProof(
  db: TrieDatabaseRef,
  rootHash: seq[byte],
  key: seq[byte]): Result[Option[seq[byte]], string] =
  var currentKey = initNibbleRange(key)

  var currentHash = rootHash

  while true:
    let node = db.get(currentHash)

    if len(node) == 0:
      return err("missing expected node")

    let next = ? getNextNode(rlpFromBytes(node), currentKey)

    case next.kind
    of EmptyValue:
      return ok(none(seq[byte]))
    of ValueNode:
      return ok(some(next.value))
    of HashNode:
      currentKey = next.restOfTheKey
      currentHash = next.nextNodeHash

proc verifyMptProof*(
    branch: seq[seq[byte]],
    rootHash: KeccakHash,
    key: seq[byte],
    value: seq[byte]): MptProofVerificationResult =
  ## Verifies provided proof of inclusion (trie branch) against provided trie
  ## root hash.
  ## Distinguishes 3 possible results:
  ## - proof is valid but key is not part of the trie
  ## - proof is invalid
  ## - proof is valid
  ## In case of valid proof, value is extracted from the leaf node and compared
  ## against provided value
  ##
  ## Main difference between this function and hexary.isValidBranch() is that
  ## this function is meant for dealing with input from untrusted sources so:
  ## - it should not have hidden assertion
  ## - it should not have surprising exceptions
  ## - it parses mpt nodes more strictly
  ##
  ## hexary.isValidBranch() is implemented via hexary trie `get` method which
  ## may contain some checks important for integrity of the trie therefore is
  ## is not really safe when receiving input from untrusted source.

  if len(branch) == 0:
    return invalidProof("empty branch")

  var db = newMemoryDB()
  for node in branch:
    if len(node) == 0:
      return invalidProof("empty mpt node in proof")
    let nodeHash = keccakHash(node)
    db.put(nodeHash.data, node)

  let
    hashBytes: seq[byte] = toSeq(rootHash.data)
    proofVerificationResult = verifyProof(db, hashBytes, key)

  if proofVerificationResult.isErr:
    return invalidProof(proofVerificationResult.error)

  let maybeProofValue = proofVerificationResult.get()

  if maybeProofValue.isNone():
    return missingKey()

  let proofValue = maybeProofValue.unsafeGet()

  if proofValue == value:
    return validProof(proofValue)
  else:
    return invalidProof("proof does not contain expected value")
