import
  os, strutils,
  util/json_testing

for file in walkDirRec("tests/cases"):
  if file.endsWith("json"):
    runTests(file)

