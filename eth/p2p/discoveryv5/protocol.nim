### This is all just temporary to support both versions
const UseDiscv51* {.booldefine.} = false

when UseDiscv51:
  import protocolv1
  export protocolv1
else:
  import protocolv0
  export protocolv0
