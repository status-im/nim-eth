import chronicles

{.used.}

when defined(chronicles_runtime_filtering):
  setLogLevel(ERROR)