import ./[base, hashes]

export base, hashes

type Account* = object
  ## Account with fields in RLP order, per `encode_account` spec function
  ## https://github.com/ethereum/execution-specs/blob/51fac24740e662844446439ceeb96a460aae0ba0/src/ethereum/paris/fork_types.py#L36
  nonce*: AccountNonce
  balance*: UInt256
  storageRoot*: Root
  codeHash*: Hash32

const
  EMPTY_ROOT_HASH* = emptyRoot
  EMPTY_CODE_HASH* = emptyHash32

func init*(
    T: type Account,
    nonce = default(AccountNonce),
    balance = default(UInt256),
    storageRoot = EMPTY_ROOT_HASH,
    codeHash = EMPTY_CODE_HASH,
): T =
  T(nonce: nonce, balance: balance, storageRoot: storageRoot, codeHash: codeHash)

const EMPTY_ACCOUNT* = Account.init()
