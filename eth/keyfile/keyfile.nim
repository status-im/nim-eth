#
#                  Ethereum KeyFile
#                 (c) Copyright 2018
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)

import nimcrypto/[bcmode, hmac, rijndael, pbkdf2, sha2, sysrand, utils, keccak],
       eth/keys, json, uuid, os, strutils, streams

const
  # Version 3 constants
  SaltSize = 16
  DKLen = 32
  MaxDKLen = 128
  ScryptR = 1
  ScryptP = 8
  Pbkdf2WorkFactor = 1_000_000
  ScryptWorkFactor = 262_144

type
  KeyFileStatus* = enum
    Success,             ## No Error
    RandomError,         ## Random generator error
    UuidError,           ## UUID generator error
    BufferOverrun,       ## Supplied buffer is too small
    IncorrectDKLen,      ## `dklen` parameter is 0 or more then MaxDKLen
    MalformedError,      ## JSON has incorrect structure
    NotImplemented,      ## Feature is not implemented
    NotSupported,        ## Feature is not supported
    EmptyMac,            ## `mac` parameter is zero length or not in
                         ## hexadecimal form
    EmptyCiphertext,     ## `ciphertext` parameter is zero length or not in
                         ## hexadecimal format
    EmptySalt,           ## `salt` parameter is zero length or not in
                         ## hexadecimal format
    EmptyIV,             ## `cipherparams.iv` parameter is zero length or not in
                         ## hexadecimal format
    IncorrectIV,         ## Size of IV vector is not equal to cipher block size
    PrfNotSupported,     ## PRF algorithm for PBKDF2 is not supported
    KdfNotSupported,     ## KDF algorithm is not supported
    CipherNotSupported,  ## `cipher` parameter is not supported
    IncorrectMac,        ## `mac` verification failed
    IncorrectPrivateKey, ## incorrect private key
    OsError,             ## OS specific error
    JsonError            ## JSON encoder/decoder error

  KdfKind* = enum
    PBKDF2,             ## PBKDF2
    SCRYPT              ## SCRYPT

  HashKind* = enum
    HashNoSupport, HashSHA2_224, HashSHA2_256, HashSHA2_384, HashSHA2_512,
    HashKECCAK224, HashKECCAK256, HashKECCAK384, HashKECCAK512,
    HashSHA3_224, HashSHA3_256, HashSHA3_384, HashSHA3_512

  CryptKind* = enum
    CipherNoSupport,    ## Cipher not supported
    AES128CTR           ## AES-128-CTR

const
  SupportedHashes = [
    "sha224", "sha256", "sha384", "sha512",
    "keccak224", "keccak256", "keccak384", "keccak512",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512"
  ]

  SupportedHashesKinds = [
    HashSHA2_224, HashSHA2_256, HashSHA2_384, HashSHA2_512,
    HashKECCAK224, HashKECCAK256, HashKECCAK384, HashKECCAK512,
    HashSHA3_224, HashSHA3_256, HashSHA3_384, HashSHA3_512
  ]

proc `$`(k: KdfKind): string =
  case k
    of SCRYPT:
      result = "scrypt"
    else:
      result = "pbkdf2"

proc `$`(k: CryptKind): string =
  case k
    of AES128CTR:
      result = "aes-128-ctr"
    else:
      result = "aes-128-ctr"

proc getPrfHash(prf: string): HashKind =
  result = HashNoSupport
  let p = prf.toLowerAscii()
  if p.startsWith("hmac-"):
    var hash = p[5..^1]
    var res = SupportedHashes.find(hash)
    if res >= 0:
      result = SupportedHashesKinds[res]
    else:
      result = HashNoSupport

proc getCipher(c: string): CryptKind =
  var cl = c.toLowerAscii()
  if cl == "aes-128-ctr":
    result = AES128CTR
  else:
    result = CipherNoSupport

proc deriveKey(password: string,
               salt: string,
               kdfkind: KdfKind,
               hashkind: HashKind,
               workfactor: int,
               output: var openarray[byte]): KeyFileStatus =
  if kdfkind == SCRYPT:
    return NotImplemented
  elif kdfkind == PBKDF2:
    var c = if workfactor == 0: Pbkdf2WorkFactor else: workfactor
    case hashkind
    of HashSHA2_224:
      var ctx: HMAC[sha224]
      discard ctx.pbkdf2(password, salt, c, output)
      result = Success
    of HashSHA2_256:
      var ctx: HMAC[sha256]
      discard ctx.pbkdf2(password, salt, c, output)
      result = Success
    of HashSHA2_384:
      var ctx: HMAC[sha384]
      discard ctx.pbkdf2(password, salt, c, output)
      result = Success
    of HashSHA2_512:
      var ctx: HMAC[sha512]
      discard ctx.pbkdf2(password, salt, c, output)
      result = Success
    of HashKECCAK224:
      var ctx: HMAC[keccak224]
      discard ctx.pbkdf2(password, salt, c, output)
      result = Success
    of HashKECCAK256:
      var ctx: HMAC[keccak256]
      discard ctx.pbkdf2(password, salt, c, output)
      result = Success
    of HashKECCAK384:
      var ctx: HMAC[keccak384]
      discard ctx.pbkdf2(password, salt, c, output)
      result = Success
    of HashKECCAK512:
      var ctx: HMAC[keccak512]
      discard ctx.pbkdf2(password, salt, c, output)
      result = Success
    of HashSHA3_224:
      var ctx: HMAC[sha3_224]
      discard ctx.pbkdf2(password, salt, c, output)
      result = Success
    of HashSHA3_256:
      var ctx: HMAC[sha3_256]
      discard ctx.pbkdf2(password, salt, c, output)
      result = Success
    of HashSHA3_384:
      var ctx: HMAC[sha3_384]
      discard ctx.pbkdf2(password, salt, c, output)
      result = Success
    of HashSHA3_512:
      var ctx: HMAC[sha3_512]
      discard ctx.pbkdf2(password, salt, c, output)
      result = Success
    else:
      result = PrfNotSupported

proc encryptKey(seckey: PrivateKey,
                cryptkind: CryptKind,
                key: openarray[byte],
                iv: openarray[byte],
                crypttext: var openarray[byte]): KeyFileStatus =
  if len(crypttext) != KeyLength:
    return BufferOverrun
  if cryptkind == AES128CTR:
    var ctx: CTR[aes128]
    ctx.init(toOpenArray(key, 0, 15), iv)
    ctx.encrypt(seckey.data, crypttext)
    ctx.clear()
    result = Success
  else:
    result = NotImplemented

proc decryptKey(ciphertext: openarray[byte],
                cryptkind: CryptKind,
                key: openarray[byte],
                iv: openarray[byte],
                plaintext: var openarray[byte]): KeyFileStatus =
  if len(ciphertext) != len(plaintext):
    return BufferOverrun
  if cryptkind == AES128CTR:
    if len(iv) != aes128.sizeBlock:
      return IncorrectIV
    var ctx: CTR[aes128]
    ctx.init(toOpenArray(key, 0, 15), iv)
    ctx.decrypt(ciphertext, plaintext)
    ctx.clear()
    result = Success
  else:
    result = NotImplemented

proc kdfParams(kdfkind: KdfKind, salt: string, workfactor: int,
               outjson: var JsonNode): KeyFileStatus =
  if kdfkind == SCRYPT:
    var wf = if workfactor == 0: ScryptWorkFactor else: workfactor
    outjson = %*
      {
        "dklen": DKLen,
        "n": wf,
        "r": ScryptR,
        "p": ScryptP,
        "salt": salt
      }
    result = Success
  elif kdfkind == PBKDF2:
    var wf = if workfactor == 0: Pbkdf2WorkFactor else: workfactor
    outjson = %*
      {
        "dklen": DKLen,
        "c": wf,
        "prf": "hmac-sha256",
        "salt": salt
      }
    result = Success
  else:
    result = NotImplemented

proc decodeHex(m: string): seq[byte] =
  if len(m) > 0:
    try:
      result = utils.fromHex(m)
    except:
      result = newSeq[byte]()
  else:
    result = newSeq[byte]()

proc decodeSalt(m: string): string =
  var sarr: seq[byte]
  if len(m) > 0:
    try:
      sarr = utils.fromHex(m)
      result = newString(len(sarr))
      copyMem(addr result[0], addr sarr[0], len(sarr))
    except:
      result = ""
  else:
    result = ""

proc compareMac(m1: openarray[byte], m2: openarray[byte]): bool =
  if len(m1) == len(m2) and len(m1) > 0:
    result = equalMem(unsafeAddr m1[0], unsafeAddr m2[0], len(m1))

proc createKeyFileJson*(seckey: PrivateKey,
                        password: string,
                        outjson: var JsonNode,
                        version: int = 3,
                        cryptkind: CryptKind = AES128CTR,
                        kdfkind: KdfKind = PBKDF2,
                        workfactor: int = 0): KeyFileStatus =
  ## Create JSON object with keyfile structure.
  ##
  ## ``seckey`` - private key, which will be stored
  ## ``password`` - encryption password
  ## ``outjson`` - result JSON object
  ## ``version`` - version of keyfile format (default is 3)
  ## ``cryptkind`` - algorithm for private key encryption
  ## (default is AES128-CTR)
  ## ``kdfkind`` - algorithm for key deriviation function (default is PBKDF2)
  ## ``workfactor`` - Key deriviation function work factor, 0 is to use
  ## default workfactor.
  var res: KeyFileStatus
  var iv: array[aes128.sizeBlock, byte]
  var ciphertext: array[KeyLength, byte]
  var salt: array[SaltSize, byte]
  var saltstr = newString(SaltSize)
  var u: UUID
  if randomBytes(iv) != aes128.sizeBlock:
    return RandomError
  if randomBytes(salt) != SaltSize:
    return RandomError
  copyMem(addr saltstr[0], addr salt[0], SaltSize)
  if uuidGenerate(u) != 1:
    return UuidError
  if kdfkind != PBKDF2:
    return NotImplemented

  var dkey = newSeq[byte](DKLen)
  res = deriveKey(password, saltstr, kdfkind, HashSHA2_256,
                  workfactor, dkey)
  if res != Success:
    return res
  res = encryptKey(seckey, cryptkind, dkey, iv, ciphertext)
  if res != Success:
    return res
  var ctx: keccak256
  ctx.init()
  ctx.update(toOpenArray(dkey, 16, 31))
  ctx.update(ciphertext)
  var mac = ctx.finish()
  ctx.clear()

  var params: JsonNode
  res = kdfParams(kdfkind, toHex(salt, true), workfactor, params)
  if res != Success:
    return res

  outjson = %*
    {
      "address": seckey.getPublicKey().toAddress(false),
      "crypto": {
        "cipher": $cryptkind,
        "cipherparams": {
          "iv": toHex(iv, true)
        },
        "ciphertext": toHex(ciphertext, true),
        "kdf": $kdfkind,
        "kdfparams": params,
        "mac": toHex(mac.data, true),
      },
      "id": $u,
      "version": version
    }
  result = Success

proc decodeKeyFileJson*(j: JsonNode,
                        password: string,
                        seckey: var PrivateKey): KeyFileStatus =
  ## Decode private key into ``seckey`` from keyfile json object ``j`` using
  ## password string ``password``.
  var
    res: KeyFileStatus
    plaintext: array[KeyLength, byte]

  var crypto = j.getOrDefault("crypto")
  if isNil(crypto):
    return MalformedError

  var kdf = crypto.getOrDefault("kdf")
  if isNil(kdf):
    return MalformedError

  var cipherparams = crypto.getOrDefault("cipherparams")
  if isNil(cipherparams):
    return MalformedError

  if kdf.getStr() == "pbkdf2":
    var params = crypto.getOrDefault("kdfparams")

    if isNil(params):
      return MalformedError

    var salt = decodeSalt(params.getOrDefault("salt").getStr())
    var ciphertext = decodeHex(crypto.getOrDefault("ciphertext").getStr())
    var mactext = decodeHex(crypto.getOrDefault("mac").getStr())
    var cryptkind = getCipher(crypto.getOrDefault("cipher").getStr())
    var iv = decodeHex(cipherparams.getOrDefault("iv").getStr())

    if len(salt) == 0:
      return EmptySalt
    if len(ciphertext) == 0:
      return EmptyCiphertext
    if len(mactext) == 0:
      return EmptyMac
    if cryptkind == CipherNoSupport:
      return CipherNotSupported

    var dklen = params.getOrDefault("dklen").getInt()
    var c = params.getOrDefault("c").getInt()
    var hash = getPrfHash(params.getOrDefault("prf").getStr())

    if hash == HashNoSupport:
      return PrfNotSupported
    if dklen == 0 or dklen > MaxDKLen:
      return IncorrectDKLen
    if len(ciphertext) != KeyLength:
      return IncorrectPrivateKey

    var dkey = newSeq[byte](dklen)
    res = deriveKey(password, salt, PBKDF2, hash, c, dkey)
    if res != Success:
      return res

    var ctx: keccak256
    ctx.init()
    ctx.update(toOpenArray(dkey, 16, 31))
    ctx.update(ciphertext)
    var mac = ctx.finish()
    if not compareMac(mac.data, mactext):
      return IncorrectMac

    res = decryptKey(ciphertext, cryptkind, dkey, iv, plaintext)
    if res != Success:
      return res
    try:
      seckey = initPrivateKey(plaintext)
    except:
      return IncorrectPrivateKey
    result = Success
  else:
    return KdfNotSupported

proc loadKeyFile*(pathname: string,
                  password: string,
                  seckey: var PrivateKey): KeyFileStatus =
  ## Load and decode private key ``seckey`` from file with pathname
  ## ``pathname``, using password string ``password``.
  var data: JsonNode
  var stream = newFileStream(pathname)
  if isNil(stream):
    return OsError

  try:
    data = parseFile(pathname)
    result = Success
  except:
    result = JsonError
  finally:
    stream.close()

  if result == Success:
    result = decodeKeyFileJson(data, password, seckey)

proc saveKeyFile*(pathname: string,
                  jobject: JsonNode): KeyFileStatus =
  ## Save JSON object ``jobject`` to file with pathname ``pathname``.
  var
    f: File
  if not f.open(pathname, fmWrite):
    return OsError
  try:
    f.write($jobject)
    result = Success
  except:
    result = OsError
  finally:
    f.close()
