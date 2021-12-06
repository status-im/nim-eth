import
  chronos

const targetDelay = milliseconds(100)

# explanation from reference impl:
# number of bytes to increase max window size by, per RTT. This is
# scaled down linearly proportional to off_target. i.e. if all packets
# in one window have 0 delay, window size will increase by this number.
# Typically it's less. TCP increases one MSS per RTT, which is 1500
const maxCwndIncreaseBytesPerRtt = 3000

const minWindowSize = 10

proc applyCongestionControl*(
  currentMaxWindowSize: uint32,
  currentSlowStart: bool,
  currentSlowStartTreshold: uint32,
  maxSndBufferSize: uint32,
  currentPacketSize: uint32,
  actualDelay: Duration,
  numOfAckedBytes: uint32,
  minRtt: Duration
): (uint32, uint32, bool) = 
  if (actualDelay.isZero() or minRtt.isZero() or numOfAckedBytes == 0):
    return (currentMaxWindowSize, currentSlowStartTreshold, currentSlowStart)
  
  # TODO add taking into account value from our delay measurmens
  let ourDelay = minRtt

  let target = targetDelay

  let offTarget = target.microseconds() - ourDelay.microseconds()
  # TODO add handling clock drift penalty

  # calculations from reference impl:
  # double window_factor = (double)min(bytes_acked, max_window) / (double)max(max_window, bytes_acked);
  # double delay_factor = off_target / target;
  # double scaled_gain = MAX_CWND_INCREASE_BYTES_PER_RTT * window_factor * delay_factor;
  
  let windowFactor = float64(min(numOfAckedBytes, currentMaxWindowSize)) / float64(max(currentMaxWindowSize, numOfAckedBytes))
  let delayFactor = float64(offTarget) / float64(target.microseconds())

  # TODO add handling of zeroing scaledGain in case of hitting max window
  let scaledGain = uint32(maxCwndIncreaseBytesPerRtt * windowFactor * delayFactor)

  let scaledWindow = currentMaxWindowSize + scaledGain

  let ledbatCwnd: uint32 = 
    if scaledWindow < minWindowSize:
      uint32(minWindowSize)
    else:
      scaledWindow

  var newSlowStart = currentSlowStart
  var newMaxWindowSize = currentMaxWindowSize
  var newSlowStartTreshold = currentSlowStartTreshold

  if currentSlowStart:
    let slowStartCwnd = currentMaxWindowSize + uint32(windowFactor * float64(currentPacketSize))

    if (slowStartCwnd > currentSlowStartTreshold):
      newSlowStart = false
    elif float64(ourDelay.microseconds()) > float64(target.microseconds()) * 0.9:
      # we are just a litte under target delay, discontinute slows start
      newSlowStart = false
      newSlowStartTreshold = currentMaxWindowSize
    else:
      newMaxWindowSize = max(slowStartCwnd, ledbatCwnd)
  else:
    newMaxWindowSize = ledbatCwnd

  newMaxWindowSize = clamp(newMaxWindowSize, minWindowSize, maxSndBufferSize)

  (newMaxWindowSize, newSlowStartTreshold, newSlowStart)



