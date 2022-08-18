import
  common/eth_types

const
  EIP1559_BASE_FEE_CHANGE_DENOMINATOR* = ##\
    ## Bounds the amount the base fee can change between blocks.
    8

  EIP1559_ELASTICITY_MULTIPLIER* = ##\
    ## Bounds the maximum gas limit an EIP-1559 block may have.
    2

  EIP1559_INITIAL_BASE_FEE* = ##\
    ## Initial base fee for Eip1559 blocks.
    1000000000.u256

proc calcEip1599BaseFee*(parentGasLimit, parentGasUsed: GasInt;
                         parentBaseFee: UInt256): UInt256 =
  ## calculates the basefee of the header.

  let parentGasTarget = parentGasLimit div EIP1559_ELASTICITY_MULTIPLIER

  # If the parent gasUsed is the same as the target, the baseFee remains
  # unchanged.
  if parentGasUsed == parentGasTarget:
    return parentBaseFee

  let parentGasDenom = parentGasTarget.u256 *
                         EIP1559_BASE_FEE_CHANGE_DENOMINATOR.u256

  if parentGasTarget < parentGasUsed:
    # If the parent block used more gas than its target, the baseFee should
    # increase.
    let
      gasUsedDelta = (parentGasUsed - parentGasTarget).u256
      baseFeeDelta = (parentBaseFee * gasUsedDelta) div parentGasDenom

    return parentBaseFee + max(baseFeeDelta, 1.u256)

  else:
    # Otherwise if the parent block used less gas than its target, the
    # baseFee should decrease.
    let
      gasUsedDelta = (parentGasTarget - parentGasUsed).u256
      baseFeeDelta = (parentBaseFee * gasUsedDelta) div parentGasDenom

    return max(parentBaseFee - baseFeeDelta, 0.u256)
