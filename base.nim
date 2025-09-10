import stint, eth/common/base_rlp

const storageProof_value = UInt256.fromDecimal("215005173230799576880935540932990999233840682152")
const expected_encoded = @[148'u8, 37, 169, 42, 88, 83, 112, 47, 25, 155, 178, 216, 5, 187, 160, 93, 103, 2, 82, 20, 168]

# Uncomment this import to allow the doAssert to work correctly
import ./desc_identifiers

doAssert rlp.encode(storageProof_value) == expected_encoded

