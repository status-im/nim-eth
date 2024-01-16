switch("passL", "-Wl,--stack,8388608")

# begin Nimble config (version 1)
when fileExists("nimble.paths"):
  include "nimble.paths"
# end Nimble config
