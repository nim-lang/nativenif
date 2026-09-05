#
#           Jorogumo — Leng → JavaScript code generator
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution, for
#    details about the copyright.
##

## The development harness: run the generator over arkham's whole hand-written
## Leng corpus and say, honestly, how much of it jorogumo can now generate — and
## for what it generates, whether node agrees with the exit code and stdout the
## native backend records.
##
## This is the coverage ladder for M3+. It is not the shipping test (that is
## `jorogumoTests` in `tests/tester.nim`, M9); it is the tool that turns "keep
## implementing ops" into a number that only goes up.
##
## Run: `nim c -r tjsgen.nim`. `--only:STEM` narrows to one fixture.

import std / [os, osproc, strutils, tables]
import nifcore, nifcoreparse
import "../arkham/core" / lengdecl
import codegen_js, jsenc

proc onlyFilter: string =
  for a in commandLineParams():
    if a.startsWith("--only:"): return a.substr("--only:".len)

proc corpusDir: string =
  for d in ["../../tests/arkham", "tests/arkham", getAppDir() / "../../tests/arkham"]:
    if dirExists(d): return d
  quit "tjsgen: the arkham corpus was not found"

proc expectFile(dir, stem, suffix: string): string =
  ## What the native backend records for this fixture: stdout (default empty)
  ## and exit code (default 0).
  let p = dir / (stem & suffix)
  if fileExists(p): readFile(p) else: ""

proc clip(s: string; n = 48): string =
  ## A comparable fixture's output is a line or two; anything longer is shown
  ## as a prefix, because a divergence is already proven by then.
  let one = s.replace("\n", "\\n")
  if one.len > n: one[0 ..< n] & "…" else: one

proc reasonOf(outp: string): string =
  ## The refusal, reduced to what is MISSING, so the report groups by cause
  ## rather than by which fixture hit it. The fixture's own path is stripped —
  ## it is on every line and says nothing about the gap.
  var line = ""
  for l in outp.split('\n'):
    if l.startsWith("jorogumo: ") or l.startsWith("Error: unhandled exception"):
      line = l
      break
  if line.len == 0: line = outp.strip.split('\n')[0]
  var m = line.replace("jorogumo: ", "").replace("Error: unhandled exception: ", "")
  m = m.split("\n  in ")[0].split(" [")[0]
  const sPre = "unsupported statement: "
  const ePre = "unsupported expression: "
  if m.startsWith(sPre): m = "statement " & m.substr(sPre.len)
  elif m.startsWith(ePre): m = "expression " & m.substr(ePre.len)
  result = m

let nodeExe = findExe("node")
if nodeExe.len == 0: quit "tjsgen: node is required — this harness runs what it emits"

let dir = corpusDir()
let only = onlyFilter()
let work = getTempDir() / "jorogumo_tjsgen"
createDir work

var
  total = 0
  emitted = 0
  matched = 0
  refused = 0
  expectedRefusals = 0
  reasons = initOrderedTable[string, int]()
  badRuns: seq[string] = @[]
  errGenerated: seq[string] = @[]

let jorogumo = getAppDir() / ("jorogumo".addFileExt(ExeExt))
if not fileExists(jorogumo): quit "tjsgen: build bin/jorogumo first"

for file in walkFiles(dir / "*.c.nif"):
  let stem = file.extractFilename.changeFileExt("").changeFileExt("")
  if only.len > 0 and stem != only: continue
  inc total
  # An `err_` fixture with no `.exitcode` and no `.output` records a construct
  # the NATIVE back end rejects: there is no behaviour to agree with, so a
  # refusal here is agreement and a generation is a difference to look at, not a
  # failure to fix.
  let isErrCase = stem.startsWith("err_") and
    not fileExists(dir / (stem & ".exitcode")) and
    not fileExists(dir / (stem & ".output"))
  let wantOut = expectFile(dir, stem, ".output").strip
  let wantCode = (let c = expectFile(dir, stem, ".exitcode"); if c.len > 0: c.strip else: "0")
  let jsPath = work / (stem & ".js")
  removeFile jsPath
  # The generator runs as a PROCESS: a refusal may come from arkham's own
  # assertions, and those are fatal in this build — an in-process harness would
  # die on the first fixture that steps outside what typenav can type. Exit
  # status is the answer, exactly as `tests/tester.nim` treats ithaqua.
  let gen = execCmdEx(quoteShell(jorogumo) & " -m:4194304 -o:" & quoteShell(jsPath) &
                      " " & quoteShell(file))
  if gen.exitCode != 0 or not fileExists(jsPath):
    inc refused
    if isErrCase:
      inc expectedRefusals
      if only.len > 0: echo "REFUSED (expected) ", stem
      continue
    let r = reasonOf(gen.output)
    reasons[r] = (if reasons.hasKey(r): reasons[r] else: 0) + 1
    if only.len > 0: echo "REFUSED ", stem, ": ", r
    continue

  inc emitted
  let r = execCmdEx(nodeExe & " " & quoteShell(jsPath))
  let gotOut = r.output.strip
  let gotCode = $r.exitCode
  if isErrCase:
    errGenerated.add stem & " -> exit " & gotCode
    if only.len > 0: echo "GENERATED AN err_ FIXTURE ", stem, " -> exit ", gotCode
    removeFile jsPath
    continue
  if gotOut == wantOut and gotCode == wantCode:
    inc matched
  else:
    badRuns.add stem & ": exit " & gotCode & " want " & wantCode &
                "; out `" & clip(gotOut) & "` want `" & clip(wantOut) & "`"
  if only.len > 0:
    echo "EMITTED ", stem, " -> exit ", gotCode, " (want ", wantCode, ")"
  removeFile jsPath

echo ""
echo emitted, " / ", total, " fixtures generate; ", matched, " / ", emitted,
     " agree with the native backend under node; ", refused, " refused (",
     expectedRefusals, " of them an `err_` fixture the native back end rejects too)"
if badRuns.len > 0:
  echo "--- wrong results ---"
  for b in badRuns[0 ..< min(badRuns.len, 15)]: echo "  ", b
if errGenerated.len > 0:
  echo "--- generated although the native back end rejects them ---"
  for b in errGenerated[0 ..< min(errGenerated.len, 15)]: echo "  ", b
if reasons.len > 0:
  echo "--- refusals by cause ---"
  for k, v in reasons: echo "  ", v, "x  ", k
