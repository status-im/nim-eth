import
  os,
  strutils,
  macros
  
const 
  prefix = "tests/"

func processFileName(name: string): string =
  result = name.replace("\\", "/")
  result = result.substr(prefix.len)
  
macro generateImports() =
  result = newStmtList()
  for file in walkDirRec("tests/fuzzing"):
    if file.endsWith("nim"):
      let name = processFileName(file)
      result.add quote do:
        import `name`
  
generateImports()
