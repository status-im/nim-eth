{.used.}

import
  std/[os, strutils, strformat],
  ./util/json_testing

template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]

const casesDir = &"{sourceDir}{DirSep}cases{DirSep}"

for file in walkDirRec(casesDir):
  if file.endsWith("json"):
    runTests(file)

