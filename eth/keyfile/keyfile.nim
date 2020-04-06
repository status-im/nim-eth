#
#                  Ethereum KeyFile
#                 (c) Copyright 2018
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)

{.push raises: [Defect].}

import nimcrypto/[bcmode, hmac, rijndael, pbkdf2, sha2, sysrand, utils, keccak],
       eth/keys, json, uuid, strutils, stew/result

export result

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
  KeyFileError* = enum
    RandomError           = "kf: Random generator error"
    UuidError             = "kf: UUID generator error"
    BufferOverrun         = "kf: Supplied buffer is too small"
    IncorrectDKLen        = "kf: `dklen` parameter is 0 or more then MaxDKLen"
    MalformedError        = "kf: JSON has incorrect structure"
    NotImplemented        = "kf: Feature is not implemented"
    NotSupported          = "kf: Feature is not supported"
    EmptyMac              = "kf: `mac` parameter is zero length or not in hexadecimal form"
    EmptyCiphertext       = "kf: `ciphertext` parameter is zero length or not in hexadecimal format"
    EmptySalt             = "kf: `salt` parameter is zero length or not in hexadecimal format"
    EmptyIV               = "kf: `cipherparams.iv` parameter is zero length or not in hexadecimal format"
    IncorrectIV           = "kf: Size of IV vector is not equal to cipher block size"
    PrfNotSupported       = "kf: PRF algorithm for PBKDF2 is not supported"
    KdfNotSupported       = "kf: KDF algorithm is not supported"
    CipherNotSupported    = "kf: `cipher` parameter is not supported"
    IncorrectMac          = "kf: `mac` verification failed"
    IncorrectPrivateKey   = "kf: incorrect private key"
    OsError               = "kf: OS specific error"
    JsonError             = "kf: JSON encoder/decoder error"

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

  KfResult*[T] = Result[T, KeyFileError]

proc mapErrTo[T, E](r: Result[T, E], v: static KeyFileError): KfResult[T] =
  r.mapErr(proc (e: E): KeyFileError = v)

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
               workfactor: int): KfResult[array[DKLen, byte]] =
  if kdfkind == PBKDF2:
    var output: array[DKLen, byte]
    var c = if workfactor == 0: Pbkdf2WorkFactor else: workfactor
    case hashkind
    of HashSHA2_224:
      var ctx: HMAC[sha224]
      discard ctx.pbkdf2(password, salt, c, output)
      ok(output)
    of HashSHA2_256:
      var ctx: HMAC[sha256]
      discard ctx.pbkdf2(password, salt, c, output)
      ok(output)
    of HashSHA2_384:
      var ctx: HMAC[sha384]
      discard ctx.pbkdf2(password, salt, c, output)
      ok(output)
    of HashSHA2_512:
      var ctx: HMAC[sha512]
      discard ctx.pbkdf2(password, salt, c, output)
      ok(output)
    of HashKECCAK224:
      var ctx: HMAC[keccak224]
      discard ctx.pbkdf2(password, salt, c, output)
      ok(output)
    of HashKECCAK256:
      var ctx: HMAC[keccak256]
      discard ctx.pbkdf2(password, salt, c, output)
      ok(output)
    of HashKECCAK384:
      var ctx: HMAC[keccak384]
      discard ctx.pbkdf2(password, salt, c, output)
      ok(output)
    of HashKECCAK512:
      var ctx: HMAC[keccak512]
      discard ctx.pbkdf2(password, salt, c, output)
      ok(output)
    of HashSHA3_224:
      var ctx: HMAC[sha3_224]
      discard ctx.pbkdf2(password, salt, c, output)
      ok(output)
    of HashSHA3_256:
      var ctx: HMAC[sha3_256]
      discard ctx.pbkdf2(password, salt, c, output)
      ok(output)
    of HashSHA3_384:
      var ctx: HMAC[sha3_384]
      discard ctx.pbkdf2(password, salt, c, output)
      ok(output)
    of HashSHA3_512:
      var ctx: HMAC[sha3_512]
      discard ctx.pbkdf2(password, salt, c, output)
      ok(output)
    else:
      err(PrfNotSupported)
  else:
    err(NotImplemented)

proc encryptKey(seckey: PrivateKey,
                cryptkind: CryptKind,
                key: openarray[byte],
                iv: openarray[byte]): KfResult[array[KeyLength, byte]] =
  if cryptkind == AES128CTR:
    var crypttext: array[KeyLength, byte]
    var ctx: CTR[aes128]
    ctx.init(toOpenArray(key, 0, 15), iv)
    ctx.encrypt(seckey.toRaw(), crypttext)
    ctx.clear()
    ok(crypttext)
  else:
    err(NotImplemented)

proc decryptKey(ciphertext: openarray[byte],
                cryptkind: CryptKind,
                key: openarray[byte],
                iv: openarray[byte]): KfResult[array[KeyLength, byte]] =
  if cryptkind == AES128CTR:
    if len(iv) != aes128.sizeBlock:
      return err(IncorrectIV)
    var plaintext: array[KeyLength, byte]
    var ctx: CTR[aes128]
    ctx.init(toOpenArray(key, 0, 15), iv)
    ctx.decrypt(ciphertext, plaintext)
    ctx.clear()
    ok(plaintext)
  else:
    err(NotImplemented)

proc kdfParams(kdfkind: KdfKind, salt: string, workfactor: int): KfResult[JsonNode] =
  if kdfkind == SCRYPT:
    let wf = if workfactor == 0: ScryptWorkFactor else: workfactor
    ok(%*
      {
        "dklen": DKLen,
        "n": wf,
        "r": ScryptR,
        "p": ScryptP,
        "salt": salt
      }
    )
  elif kdfkind == PBKDF2:
    let wf = if workfactor == 0: Pbkdf2WorkFactor else: workfactor
    ok(%*
      {
        "dklen": DKLen,
        "c": wf,
        "prf": "hmac-sha256",
        "salt": salt
      }
    )
  else:
    err(NotImplemented)

proc decodeHex(m: string): seq[byte] =
  if len(m) > 0:
    try:
      result = utils.fromHex(m)
    except CatchableError:
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
    except CatchableError:
      result = ""
  else:
    result = ""

proc compareMac(m1: openarray[byte], m2: openarray[byte]): bool =
  if len(m1) == len(m2) and len(m1) > 0:
    result = equalMem(unsafeAddr m1[0], unsafeAddr m2[0], len(m1))

proc createKeyFileJson*(seckey: PrivateKey,
                        password: string,
                        version: int = 3,
                        cryptkind: CryptKind = AES128CTR,
                        kdfkind: KdfKind = PBKDF2,
                        workfactor: int = 0): KfResult[JsonNode] =
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
  var iv: array[aes128.sizeBlock, byte]
  var salt: array[SaltSize, byte]
  var saltstr = newString(SaltSize)
  if randomBytes(iv) != aes128.sizeBlock:
    return err(RandomError)
  if randomBytes(salt) != SaltSize:
    return err(RandomError)
  copyMem(addr saltstr[0], addr salt[0], SaltSize)

  let u = ? uuidGenerate().mapErrTo(UuidError)

  if kdfkind != PBKDF2:
    return err(NotImplemented)

  let
    dkey = ? deriveKey(password, saltstr, kdfkind, HashSHA2_256, workfactor)
    ciphertext = ? encryptKey(seckey, cryptkind, dkey, iv)

  var ctx: keccak256
  ctx.init()
  ctx.update(toOpenArray(dkey, 16, 31))
  ctx.update(ciphertext)
  var mac = ctx.finish()
  ctx.clear()

  let params = ? kdfParams(kdfkind, toHex(salt, true), workfactor)

  ok(%*
    {
      "address": (? seckey.toPublicKey().mapErrTo(IncorrectPrivateKey)).toAddress(false),
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
  )

proc decodeKeyFileJson*(j: JsonNode,
                        password: string): KfResult[PrivateKey] =
  ## Decode private key into ``seckey`` from keyfile json object ``j`` using
  ## password string ``password``.
  var crypto = j.getOrDefault("crypto")
  if isNil(crypto):
    return err(MalformedError)

  var kdf = crypto.getOrDefault("kdf")
  if isNil(kdf):
    return err(MalformedError)

  var cipherparams = crypto.getOrDefault("cipherparams")
  if isNil(cipherparams):
    return err(MalformedError)

  if kdf.getStr() == "pbkdf2":
    var params = crypto.getOrDefault("kdfparams")

    if isNil(params):
      return err(MalformedError)

    var salt = decodeSalt(params.getOrDefault("salt").getStr())
    var ciphertext = decodeHex(crypto.getOrDefault("ciphertext").getStr())
    var mactext = decodeHex(crypto.getOrDefault("mac").getStr())
    var cryptkind = getCipher(crypto.getOrDefault("cipher").getStr())
    var iv = decodeHex(cipherparams.getOrDefault("iv").getStr())

    if len(salt) == 0:
      return err(EmptySalt)
    if len(ciphertext) == 0:
      return err(EmptyCiphertext)
    if len(mactext) == 0:
      return err(EmptyMac)
    if cryptkind == CipherNoSupport:
      return err(CipherNotSupported)

    var dklen = params.getOrDefault("dklen").getInt()
    var c = params.getOrDefault("c").getInt()
    var hash = getPrfHash(params.getOrDefault("prf").getStr())

    if hash == HashNoSupport:
      return err(PrfNotSupported)
    if dklen == 0 or dklen > MaxDKLen:
      return err(IncorrectDKLen)
    if len(ciphertext) != KeyLength:
      return err(IncorrectPrivateKey)

    let dkey = ? deriveKey(password, salt, PBKDF2, hash, c)

    var ctx: keccak256
    ctx.init()
    ctx.update(toOpenArray(dkey, 16, 31))
    ctx.update(ciphertext)
    var mac = ctx.finish()
    if not compareMac(mac.data, mactext):
      return err(IncorrectMac)

    let plaintext = ? decryptKey(ciphertext, cryptkind, dkey, iv)

    PrivateKey.fromRaw(plaintext).mapErrTo(IncorrectPrivateKey)
  else:
    err(KdfNotSupported)

proc loadKeyFile*(pathname: string,
                  password: string): KfResult[PrivateKey] =
  ## Load and decode private key ``seckey`` from file with pathname
  ## ``pathname``, using password string ``password``.
  var data: JsonNode
  try:
    data = json.parseFile(pathname)
  except JsonParsingError:
    return err(JsonError)
  except Exception: # json raises Exception
    return err(OsError)

  decodeKeyFileJson(data, password)

proc saveKeyFile*(pathname: string,
                  jobject: JsonNode): KfResult[void] =
  ## Save JSON object ``jobject`` to file with pathname ``pathname``.
  var
    f: File
  if not f.open(pathname, fmWrite):
    return err(OsError)
  try:
    f.write($jobject)
    ok()
  except CatchableError:
    err(OsError)
  finally:
    f.close()
