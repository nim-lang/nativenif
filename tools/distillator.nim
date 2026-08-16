## distillator — distills gcc's code generation into forms the native backend
## can learn from. Subsumes `tools/cmpcodegen.py` and adds a disassembly →
## asm-NIF translator, so a gcc-compiled function can eventually be spliced
## into a nifasm-linked program (the "ceiling experiment") and so we know —
## measured, not guessed — which instructions/operand forms `doc/instructions.md`
## is missing before arkham could ever emit them.
##
##   distillator compare  <workload.nim> [func-substr ...]
##       Build the workload through BOTH backends (`nimony n` vs `nimony c
##       --passC:-O3`), disassemble, write per-function side-by-side listings
##       under listings/ and print an instruction/byte ratio summary.
##
##   distillator translate <workload.nim> <func-substr ...>
##       Disassemble the gcc -O3 build, translate the named functions to
##       asm-NIF text (listings/<func>.asm.nif) and write a per-function
##       report of everything that could not be expressed.
##
##   distillator audit    <workload.nim>
##       Run the translator over EVERY gcc function and print a histogram of
##       the inexpressible instruction/operand forms — the prioritized
##       worklist for extending instructions.md/nifasm.
##
##   distillator splice   <workload.nim> <func-substr ...> [--run]
##       The ceiling experiment: replace the named arkham proc BODIES with the
##       translated gcc -O3 code — arkham's header (params/result/clobber, its
##       ABI is plain SysV) stays, calls become `(prepare …)` glue against the
##       native callees' signatures, TLS/global symbols are name-mapped, and
##       push/pop glue preserves every volatile the header doesn't declare
##       clobbered. Links listings/splice/{native,spliced}.elf; --run executes
##       both and compares their output.
##
## The instruction vocabulary is read from doc/instructions.md AT COMPILE TIME
## (the same table gen_instructions.nim generates nifasm's tags/model from), so
## this tool cannot drift from the model: rebuild it when the table changes,
## exactly like nifasm itself.
##
## Env: NIMONY_BIN — dir holding nimony/arkham/nifasm (default: ../nimony/bin
## relative to this repository).

import std / [os, osproc, streams, strutils, tables, sets, algorithm, sequtils]

const InstructionsMd = staticRead("../doc/instructions.md")

# ---------------------------------------------------------------- model table

proc parseTagTable(md: string): seq[(string, string)] =
  ## Every `| `(tag …)` | Enums | …` row as (tagName, enumsCell).
  result = @[]
  for line in md.splitLines:
    let l = line.strip
    if not l.startsWith("|"): continue
    let cells = l.split('|')
    if cells.len < 3: continue
    let c1 = cells[1].strip
    if not c1.startsWith("`("): continue
    var name = ""
    var i = 2
    while i < c1.len and c1[i] notin {' ', ')', '`'}:
      name.add c1[i]
      inc i
    if name.len > 0:
      result.add (name, cells[2].strip)

const TagTable = parseTagTable(InstructionsMd)

proc tagsFor(enumName: string): HashSet[string] =
  result = initHashSet[string]()
  for (name, enums) in TagTable:
    if enumName in enums:
      result.incl name

let x64InstTags = tagsFor("X64Inst")   ## every instruction tag the model has

# ------------------------------------------------------------------- plumbing

proc repoDir(): string =
  ## Repository root: the tool lives in <repo>/tools or <repo>/bin.
  result = getAppDir().parentDir

proc binDir(): string =
  result = getEnv("NIMONY_BIN")
  if result.len == 0:
    result = repoDir() / ".." / "nimony" / "bin"

proc tool(name: string): string =
  result = binDir() / name
  if not fileExists(result):
    quit "missing tool: " & result & " (set NIMONY_BIN)"

proc run(args: seq[string]; failOk = false): string =
  ## Run a command; stderr is merged into the result (nifasm prints the symmap
  ## there and is otherwise quiet, so the merge is harmless and deadlock-free).
  var p = startProcess(args[0], args = args[1..^1],
                       options = {poUsePath, poStdErrToStdOut})
  result = p.outputStream.readAll
  let code = p.waitForExit
  p.close
  if code != 0 and not failOk:
    quit "FAILED: " & args.join(" ") & "\n" & result

proc parseHex(s: string): int64 =
  ## -1 on a non-hex string; 16-digit values with the top bit set come back
  ## as their two's-complement reinterpretation (how fs:0xffff… TLS offsets
  ## are meant to be read anyway).
  if s.len == 0 or s.len > 16: return -1
  var u: uint64 = 0
  for c in s:
    let d = case c
            of '0'..'9': ord(c) - ord('0')
            of 'a'..'f': ord(c) - ord('a') + 10
            of 'A'..'F': ord(c) - ord('A') + 10
            else: return -1
    u = u * 16 + uint64(d)
  result = cast[int64](u)

proc isHex(s: string): bool =
  s.len > 0 and s.allCharsInSet(HexDigits)

proc hexStr(v: int64): string =
  ## "0x"-less lowercase hex without leading zeros ("400000", not "00004…").
  result = v.toHex.toLowerAscii
  var i = 0
  while i < result.len - 1 and result[i] == '0': inc i
  result = result.substr(i)

# ------------------------------------------------------------- native build

type
  SymSpan = object
    name: string
    lo, hi: int64          ## hi == -1: open-ended (last symbol)

proc buildNative(src, work: string): tuple[elf: string; spans: seq[SymSpan]] =
  ## Compile with `nimony n`, link with --symmap, return the ELF and the
  ## per-proc address spans recovered from the (symbol-table-free) binary.
  let nc = work / "nat"
  createDir nc
  discard run(@[tool("nimony"), "n", "--silentMake", "--isMain", "--opt:speed",
                "--nimcache:" & nc, src])
  var asmFiles: seq[string] = @[]
  for f in walkDirRec(nc):
    if f.endsWith(".asm.nif"): asmFiles.add f
  if asmFiles.len == 0:
    quit "no .asm.nif produced under " & nc
  # All module .asm.nifs land in one subdir named after the MAIN module; the
  # main asm.nif shares that name and MUST be linked first (it holds _start).
  let d = asmFiles[0].parentDir
  let main = d / (d.extractFilename & ".asm.nif")
  var others = asmFiles.filterIt(it != main)
  others.sort
  result.elf = work / "native.elf"
  let outp = run(@[tool("nifasm"), "--symmap", "-o:" & result.elf, main] & others)
  var syms: seq[(int64, string)] = @[]
  for line in outp.splitLines:
    let parts = line.strip.splitWhitespace
    if parts.len >= 2 and parts[0].startsWith("0x"):
      let a = parseHex(parts[0][2..^1])
      if a >= 0: syms.add (a, parts[1])
  syms.sort
  result.spans = @[]
  for i, (a, n) in syms:
    let hi = if i + 1 < syms.len: syms[i+1][0] else: -1'i64
    result.spans.add SymSpan(name: n, lo: a, hi: hi)

proc loadBaseVaddr(elf: string): int64 =
  ## Lowest LOAD-segment vaddr (nifasm ELF has program headers, no sections).
  let outp = run(@["readelf", "-lW", elf])
  for line in outp.splitLines:
    let p = line.strip.splitWhitespace
    if p.len >= 3 and p[0] == "LOAD":
      let a = parseHex(p[2].replace("0x", ""))
      if a >= 0: return a
  result = 0x400000  # nifasm's fixed default

type
  DisLine = object
    address: int64
    text: string

proc disasmNative(elf: string; spans: seq[SymSpan]):
    tuple[full: string; insns: seq[DisLine]] =
  let base = loadBaseVaddr(elf)
  let outp = run(@["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
                   "-M", "intel", "--adjust-vma=0x" & base.hexStr,
                   elf])
  var insns: seq[DisLine] = @[]
  for line in outp.splitLines:
    let t = line.strip
    let colon = t.find(':')
    if colon > 0 and isHex(t[0 ..< colon]):
      insns.add DisLine(address: parseHex(t[0 ..< colon]), text: line)
  var starts = initTable[int64, string]()
  for sp in spans: starts[sp.lo] = sp.name
  var full: seq[string] = @[]
  for ins in insns:
    if ins.address in starts:
      full.add ""
      full.add starts[ins.address] & ":  # 0x" & ins.address.hexStr
    full.add ins.text
  result = (full.join("\n") & "\n", insns)

proc sliceNative(insns: seq[DisLine]; sp: SymSpan): seq[string] =
  result = @[]
  for ins in insns:
    if ins.address >= sp.lo and (sp.hi < 0 or ins.address < sp.hi):
      result.add ins.text

const GccSpliceFlags = @[
  # These flags shape the gcc build to mirror the SPLICE TARGET (a static,
  # libc-free nifasm ELF):
  #  -fno-jump-tables      label addresses baked into rodata are outside the model
  #  -ftls-model=local-exec  every TLS access becomes a mappable fs:offset
  #  -fno-stack-protector  the canary (fs:0x28) is glibc scaffolding
  #  -no-pie               direct calls/addresses, no PLT/GOT indirection
  #  -fno-ipa-cp-clone / -fno-ipa-sra   .constprop/.isra clones change a
  #     function's SIGNATURE, which would defeat the gcc↔native call mapping
  #  -fno-partial-inlining   .part.N clones likewise break the name mapping
  #  -g                      DWARF signatures guard the name mapping: the two
  #     pipelines assign overload ORDINALS independently, so an equal mangled
  #     name can denote a different overload — compare param count/return-ness
  #     against the native header before trusting a match
  "--passC:-fno-jump-tables", "--passC:-ftls-model=local-exec",
  "--passC:-fno-stack-protector", "--passC:-fno-ipa-cp-clone",
  "--passC:-fno-ipa-sra", "--passC:-fno-partial-inlining", "--passC:-g",
  "--passL:-no-pie"]

# --------------------------------------------------------------- gcc build

proc buildGcc(src, work: string; extraFlags: seq[string]): string =
  let nc = work / "gcc"
  createDir nc
  var cmd = @[tool("nimony"), "c", "--silentMake", "--isMain", "--opt:speed",
              "--passC:-O3"]
  cmd.add extraFlags
  cmd.add "--nimcache:" & nc
  cmd.add src
  discard run(cmd)
  for f in walkDirRec(nc):
    let base = f.extractFilename
    if '.' notin base and fpUserExec in getFilePermissions(f):
      return f
  quit "no executable produced under " & nc

type
  GccFunc = object
    name: string
    address: int64
    lines: seq[string]     ## raw objdump instruction lines

proc disasmGcc(exe: string): tuple[full: string; funcs: seq[GccFunc]] =
  let outp = run(@["objdump", "-d", "--no-show-raw-insn", "-M", "intel", exe])
  var funcs: seq[GccFunc] = @[]
  var full: seq[string] = @[]
  for line in outp.splitLines:
    # Function headers: "0000000000401230 <name>:"
    let lt = line.strip
    let lb = lt.find(" <")
    if lb > 0 and lt.endsWith(">:") and isHex(lt[0 ..< lb]):
      funcs.add GccFunc(name: lt[lb+2 ..< lt.len-2], address: parseHex(lt[0 ..< lb]))
      full.add ""
      full.add line
      continue
    full.add line
    if funcs.len > 0:
      let t = line.strip
      let colon = t.find(':')
      if colon > 0 and isHex(t[0 ..< colon]):
        funcs[^1].lines.add line
  result = (full.join("\n") & "\n", funcs)

# -------------------------------------------------------- gcc ELF symbols

type
  ElfSym = object
    value: int64
    size: int64
    kind: string           ## FUNC / OBJECT / TLS / NOTYPE
    name: string

  ElfInfo = object
    syms: seq[ElfSym]
    tlsMemSize, tlsAlign: int64

proc readElfInfo(exe: string): ElfInfo =
  result = ElfInfo(syms: @[], tlsMemSize: 0, tlsAlign: 1)
  let symOut = run(@["readelf", "-sW", exe])
  for line in symOut.splitLines:
    #    12: 0000000000404040     8 OBJECT  GLOBAL DEFAULT   24 name
    let p = line.strip.splitWhitespace
    if p.len >= 8 and p[0].endsWith(":") and isHex(p[1]):
      result.syms.add ElfSym(value: parseHex(p[1]),
                             size: try: parseBiggestInt(p[2]) except CatchableError: 0,
                             kind: p[3], name: p[7])
  let segOut = run(@["readelf", "-lW", exe])
  for line in segOut.splitLines:
    let p = line.strip.splitWhitespace
    #  TLS  offset vaddr paddr filesz memsz flags align
    if p.len >= 8 and p[0] == "TLS":
      result.tlsMemSize = parseHex(p[5].replace("0x", ""))
      result.tlsAlign = parseHex(p[7].replace("0x", ""))

proc symbolAt(info: ElfInfo; address: int64): string =
  ## Best OBJECT/FUNC symbol covering `address`; "" if anonymous.
  for s in info.syms:
    if s.kind in ["OBJECT", "FUNC"] and address >= s.value and
       (address < s.value + max(s.size, 1)):
      return s.name
  result = ""

proc readDwarfSigs(exe: string): Table[string, tuple[nparams: int; hasRet: bool]] =
  ## C-level signatures from DWARF: per function the formal-parameter count
  ## and whether it returns a value. This is the wrong-overload guard — the
  ## mangled-name map alone cannot distinguish overloads whose ordinals the
  ## two pipelines assigned differently.
  result = initTable[string, tuple[nparams: int; hasRet: bool]]()
  let outp = run(@["objdump", "--dwarf=info", exe], failOk = true)
  var cur = ""
  var nparams = 0
  var hasRet = false
  var depth = -1
  var inAttrs = false          # between the subprogram tag and its first child
  proc flush(r: var Table[string, tuple[nparams: int; hasRet: bool]];
             cur: string; nparams: int; hasRet: bool) =
    if cur.len == 0: return
    # An extern DECLARATION entry may carry less info than the definition —
    # keep the richer one.
    if cur in r and r[cur].nparams >= nparams: return
    r[cur] = (nparams, hasRet)
  for line in outp.splitLines:
    let t = line.strip
    # DIE lines look like `<1><1cb4>: … (DW_TAG_subprogram)`; the localized
    # objdump translates "Abbrev Number", so key on the structural prefix.
    if t.len > 4 and t[0] == '<' and t[1] in {'0'..'9'} and t[2] == '>' and
       t[3] == '<':
      let d = ord(t[1]) - ord('0')
      if "(DW_TAG_subprogram)" in t:
        flush(result, cur, nparams, hasRet)
        cur = ""
        nparams = 0
        hasRet = false
        depth = d
        inAttrs = true
      elif depth >= 0 and d <= depth:
        flush(result, cur, nparams, hasRet)
        cur = ""
        depth = -1
        inAttrs = false
      else:
        inAttrs = false
        # Only DIRECT children: inlined subroutines nested deeper carry their
        # own formal_parameter DIEs.
        if depth >= 0 and d == depth + 1 and "(DW_TAG_formal_parameter)" in t:
          inc nparams
    elif inAttrs:
      if "DW_AT_name" in t:
        let colon = t.rfind(':')
        if colon > 0: cur = t[colon+1 .. ^1].strip
      elif "DW_AT_type" in t:
        hasRet = true
  flush(result, cur, nparams, hasRet)

proc tlsSymbolFor(info: ElfInfo; fsOffset: int64):
    tuple[name: string; delta: int64] =
  ## Local-exec TLS: `fs:NEG` addresses the TLS block that sits directly below
  ## the thread pointer; a variable at st_value v lives at
  ## fs:(v - alignUp(tlsMemSize, tlsAlign)). An access may land INSIDE a
  ## variable (a field of a TLS aggregate) — returned as name+delta.
  result = ("", 0)
  if info.tlsMemSize == 0: return
  let blockSize = (info.tlsMemSize + info.tlsAlign - 1) and not (info.tlsAlign - 1)
  let tlsPos = fsOffset + blockSize        # position within the TLS block
  for s in info.syms:
    if s.kind == "TLS" and tlsPos >= s.value and
       tlsPos < s.value + max(s.size, 1):
      return (s.name, tlsPos - s.value)

const
  Gpr64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
           "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
  Gpr32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
           "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"]
  Gpr16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
           "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"]
  Gpr8  = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
           "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"]
  Gpr8High = ["ah", "ch", "dh", "bh"]

# ------------------------------------------------- native .asm.nif headers

type
  NativeProc = object
    declName: string       ## as written in the file, e.g. "rawDealloc.0."
    fullName: string       ## completed with the module, "rawDealloc.0.sysvq0asl"
    params: seq[tuple[name: string; regs: seq[string]]]
                           ## per param the GPR(s) it occupies — one for a
                           ## scalar, two for a ≤16B by-value aggregate
                           ## (`(regs (rdi) (rsi))`), empty for stack/xmm
    scalarOk: bool         ## every param occupies at least one GPR
    hasResult: bool
    resultName: string
    resultRegs: seq[string]  ## ["rax"] scalar, ["rax","rdx"] pair aggregate
    clobbers: seq[string]
    bodyStart, bodyEnd: int  ## span of the `(stmts …)` body in the file text

  NativeModule = object
    file, module: string
    text: string
    procs: seq[NativeProc]
    dataNames: seq[string]   ## gvar/tvar/rodata declared names

proc matchParen(t: string; start: int): int =
  ## `t[start] == '('`; index just past the matching ')'. Strings are opaque
  ## (NIF escapes an embedded quote, so the next raw '"' terminates).
  var depth = 0
  var i = start
  while i < t.len:
    case t[i]
    of '"':
      inc i
      while i < t.len and t[i] != '"': inc i
    of '(': inc depth
    of ')':
      dec depth
      if depth == 0: return i + 1
    else: discard
    inc i
  result = t.len

proc skipNifWs(t: string; i: var int) =
  while i < t.len and t[i] in {' ', '\n', '\t', '\r'}: inc i

proc readNifAtom(t: string; i: var int): string =
  result = ""
  while i < t.len and t[i] notin {' ', '\n', '\t', '\r', '(', ')'}:
    result.add t[i]
    inc i

proc childTag(t: string; start: int): string =
  ## The tag word of the paren tree starting at `start`.
  var i = start + 1
  result = readNifAtom(t, i)

proc parseRegParen(t: string; start: int): string =
  ## "(rdi)" → "rdi"; anything else (stack slot, regs pair) → "".
  var i = start + 1
  let a = readNifAtom(t, i)
  skipNifWs(t, i)
  if i < t.len and t[i] == ')' and a in Gpr64: a else: ""

proc parseLocRegs(t: string; start: int): seq[string] =
  ## A param/result LOCATION as its GPR list: "(rdi)" → @["rdi"],
  ## "(regs (rdi) (rsi))" → @["rdi", "rsi"], stack/xmm → @[].
  result = @[]
  let single = parseRegParen(t, start)
  if single.len > 0:
    return @[single]
  if childTag(t, start) == "regs":
    var i = start + len("(regs")
    let stop = matchParen(t, start)
    while true:
      skipNifWs(t, i)
      if i >= stop - 1 or t[i] != '(': break
      let e = matchParen(t, i)
      let r = parseRegParen(t, i)
      if r.len == 0: return @[]      # a non-GPR word: not spliceable
      result.add r
      i = e

proc parseNativeProc(t: string; start, stop: int): NativeProc =
  result = NativeProc(scalarOk: true)
  var i = start + len("(proc")
  skipNifWs(t, i)
  if i < t.len and t[i] == ':': inc i
  result.declName = readNifAtom(t, i)
  while true:
    skipNifWs(t, i)
    if i >= stop or t[i] != '(': break
    let cEnd = matchParen(t, i)
    let tag = childTag(t, i)
    case tag
    of "params":
      var j = i + len("(params")
      while true:
        skipNifWs(t, j)
        if j >= cEnd - 1 or t[j] != '(': break
        let pEnd = matchParen(t, j)
        if childTag(t, j) == "param":
          var k = j + len("(param")
          skipNifWs(t, k)
          if k < t.len and t[k] == ':': inc k
          let pname = readNifAtom(t, k)
          skipNifWs(t, k)
          let regs = if k < t.len and t[k] == '(': parseLocRegs(t, k)
                     else: newSeq[string]()
          result.params.add (pname, regs)
          if regs.len == 0: result.scalarOk = false
        j = pEnd
    of "result":
      var j = i + len("(result")
      skipNifWs(t, j)
      if j < cEnd - 1 and t[j] == ':':
        inc j
        result.hasResult = true
        result.resultName = readNifAtom(t, j)
        skipNifWs(t, j)
        if j < t.len and t[j] == '(':
          result.resultRegs = parseLocRegs(t, j)
    of "clobber":
      var j = i + len("(clobber")
      while true:
        skipNifWs(t, j)
        if j >= cEnd - 1 or t[j] != '(': break
        let rEnd = matchParen(t, j)
        result.clobbers.add childTag(t, j)
        j = rEnd
    of "stmts":
      result.bodyStart = i
      result.bodyEnd = cEnd
    else: discard
    i = cEnd

proc parseNativeModule(path: string): NativeModule =
  result = NativeModule(file: path,
                        module: path.extractFilename.split('.')[0],
                        text: readFile(path))
  let t = result.text
  var i = t.find("(stmts")
  if i < 0: return
  i += len("(stmts")
  while true:
    skipNifWs(t, i)
    if i >= t.len or t[i] != '(': break
    let cEnd = matchParen(t, i)
    let tag = childTag(t, i)
    if tag == "proc":
      var p = parseNativeProc(t, i, cEnd)
      p.fullName = if p.declName.endsWith("."): p.declName & result.module
                   else: p.declName
      if p.bodyEnd > 0: result.procs.add p
    elif tag in ["gvar", "tvar", "rodata"]:
      var j = i + 1 + tag.len
      skipNifWs(t, j)
      if j < t.len and t[j] == ':':
        inc j
        result.dataNames.add readNifAtom(t, j)
    i = cEnd

type
  SpliceEnv = object
    procs: Table[string, NativeProc]     ## gcc-mangled key → signature
    procModule: Table[string, string]    ## gcc key → declaring module
    data: Table[string, tuple[declName, module: string]]  ## gcc key → data sym
    targetModule: string                 ## module of the proc being spliced
    usedGccrt: bool                      ## a spliced body calls a gcc-synthesized
                                         ## libc routine → link the injected
                                         ## `gccrt` module providing it
    dwarf: Table[string, tuple[nparams: int; hasRet: bool]]
                                         ## gcc-side C signatures — the
                                         ## wrong-overload guard for the map

proc gccKey(fullName: string): string = fullName.replace(".", "_")

proc buildSpliceEnv(mods: seq[NativeModule]): SpliceEnv =
  result = SpliceEnv(procs: initTable[string, NativeProc](),
                     procModule: initTable[string, string](),
                     data: initTable[string, tuple[declName, module: string]]())
  for m in mods:
    for p in m.procs:
      result.procs[gccKey(p.fullName)] = p
      result.procModule[gccKey(p.fullName)] = m.module
    for d in m.dataNames:
      let full = if d.endsWith("."): d & m.module else: d
      result.data[gccKey(full)] = (d, m.module)

proc procSpelling(env: SpliceEnv; key: string): string =
  ## How the target module references this proc: the declared (trailing-dot)
  ## spelling for a same-module callee, the full name for a foreign one —
  ## exactly what arkham itself emits.
  let p = env.procs[key]
  if env.procModule[key] == env.targetModule: p.declName else: p.fullName

proc dataSpelling(env: SpliceEnv; key: string): string =
  let (d, m) = env.data[key]
  if m == env.targetModule: d
  elif d.endsWith("."): d & m
  else: d

# ---------------------------------------------------------- intel operands

type
  OpKind = enum opReg, opXmm, opImm, opMem, opTarget, opBad

  IOperand = object
    kind: OpKind
    reg: string            ## canonical 64-bit gpr name or xmmN
    high8: bool            ## ah/bh/ch/dh: bits 8..15 of the canonical reg
    bits: int              ## operand width in bits (0 = unknown)
    imm: int64
    base, index: string    ## mem: canonical reg names, "" if absent
    scale: int
    disp: int64
    seg: string            ## "fs" for TLS accesses
    ripTarget: int64       ## absolute target of a rip-relative operand, -1 if n/a
    target: int64          ## opTarget: branch/call destination
    targetSym: string
    text: string           ## original spelling, for reports


proc regInfo(name: string): tuple[canon: string; bits: int] =
  for i, r in Gpr64:
    if name == r: return (r, 64)
  for i, r in Gpr32:
    if name == r: return (Gpr64[i], 32)
  for i, r in Gpr16:
    if name == r: return (Gpr64[i], 16)
  for i, r in Gpr8:
    if name == r: return (Gpr64[i], 8)
  for i, r in Gpr8High:
    if name == r: return ("!high8:" & name, 8)
  if name.startsWith("xmm") and name.substr(3).allCharsInSet(Digits):
    return (name, 128)
  result = ("", 0)

proc parseImmText(s: string): tuple[ok: bool; val: int64] =
  var t = s
  var negate = false
  if t.startsWith("-"):
    negate = true
    t = t.substr(1)
  if t.startsWith("0x"):
    if not isHex(t.substr(2)): return (false, 0)
    let v = parseHex(t.substr(2))
    return (true, if negate: -v else: v)
  if t.len > 0 and t.allCharsInSet(Digits):
    return (true, (if negate: -1 else: 1) * parseBiggestInt(t))
  result = (false, 0)

proc parseMemInside(op: var IOperand; inside: string): bool =
  ## "[rax+rbx*4+0x10]" body → base/index/scale/disp. Also "rip+0x2e34".
  op.scale = 1
  var i = 0
  var sign = 1
  while i < inside.len:
    var j = i
    while j < inside.len and inside[j] notin {'+', '-'}: inc j
    let term = inside[i ..< j]
    if term == "rip":
      op.base = "rip"
    else:
      let star = term.find('*')
      if star >= 0:
        let (canon, bits) = regInfo(term[0 ..< star])
        if canon == "" or bits != 64: return false
        op.index = canon
        op.scale = try: parseInt(term[star+1 .. ^1]) except CatchableError: -1
        if op.scale notin [1, 2, 4, 8]: return false
      else:
        let (canon, bits) = regInfo(term)
        if canon != "":
          if bits != 64: return false        # 32-bit address regs: not emitted at -O3
          if op.base == "": op.base = canon
          elif op.index == "": op.index = canon
          else: return false
        else:
          let (ok, v) = parseImmText(term)
          if not ok: return false
          op.disp += sign * v
    if j < inside.len:
      sign = if inside[j] == '-': -1 else: 1
    i = j + 1
  result = true

proc parseOperandText(s: string): IOperand =
  result = IOperand(kind: opBad, ripTarget: -1, scale: 1, text: s)
  var t = s.strip
  # Size prefix
  var bits = 0
  for (prefix, b) in [("BYTE PTR ", 8), ("WORD PTR ", 16), ("DWORD PTR ", 32),
                      ("QWORD PTR ", 64), ("XMMWORD PTR ", 128),
                      ("TBYTE PTR ", 80)]:
    if t.startsWith(prefix):
      bits = b
      t = t.substr(prefix.len).strip
      break
  # Segment prefix. es/ds/cs/ss are flat-model defaults (string ops spell them
  # out) — only fs/gs carry meaning (TLS).
  var seg = ""
  for sp in ["fs:", "gs:", "cs:", "ds:", "es:", "ss:"]:
    if t.startsWith(sp):
      if sp in ["fs:", "gs:"]: seg = sp[0..1]
      t = t.substr(3)
      break
  if t.startsWith("["):
    let close = t.rfind(']')
    if close < 0: return
    result.kind = opMem
    result.bits = bits
    result.seg = seg
    if not parseMemInside(result, t[1 ..< close]):
      result.kind = opBad
    return
  if seg.len > 0:
    # "fs:0x28" — absolute segment-relative address.
    let (ok, v) = parseImmText(t)
    if not ok: return
    result.kind = opMem
    result.bits = bits
    result.seg = seg
    result.disp = v
    return
  if bits > 0:
    return                          # "QWORD PTR" without brackets: unexpected
  let (canon, rbits) = regInfo(t)
  if canon != "":
    if canon.startsWith("!high8:"):       # ah/bh/ch/dh
      result.kind = opReg
      result.high8 = true
      result.bits = 8
      result.reg = Gpr64[Gpr8High.find(canon[7..^1])]
      return
    result.kind = if rbits == 128: opXmm else: opReg
    result.reg = canon
    result.bits = rbits
    return
  let (ok, v) = parseImmText(t)
  if ok:
    result.kind = opImm
    result.imm = v
    result.bits = 0

type
  Insn = object
    address: int64
    mnemonic: string
    prefix: string          ## "lock", "rep", …
    ops: seq[IOperand]
    target: int64           ## branch/call destination (-1 if none)
    targetSym: string
    comment: string         ## objdump's "# addr <sym>" tail
    raw: string

const
  JccMnemonics = ["jmp", "je", "jz", "jne", "jnz", "jg", "jng", "jge", "jnge",
                  "ja", "jna", "jae", "jnae", "jl", "jle", "jb", "jbe", "jo",
                  "jno", "jp", "jnp", "js", "jns", "call"]
  DropMnemonics = ["nop", "nopw", "nopl", "endbr64", "hlt", "int3",
                   "cs", "data16"]

proc parseInsnLine(line: string): Insn =
  ## "  401234:\tmov    rax,QWORD PTR [rbx+0x8]        # comment"
  result = Insn(target: -1, raw: line)
  var t = line.strip
  let colon = t.find(':')
  if colon <= 0 or not isHex(t[0 ..< colon]):
    result.mnemonic = ""
    return
  result.address = parseHex(t[0 ..< colon])
  t = t.substr(colon + 1).strip
  # Comment tail
  let hash = t.find(" #")
  if hash >= 0:
    result.comment = t.substr(hash + 2).strip
    t = t[0 ..< hash].strip
  if t.len == 0:
    result.mnemonic = ""
    return
  var sp = t.find(' ')
  if sp < 0: sp = t.len
  result.mnemonic = t[0 ..< sp]
  t = t.substr(sp).strip
  # Prefixes
  while result.mnemonic in ["lock", "rep", "repz", "repnz", "bnd", "notrack"]:
    if result.mnemonic == "lock": result.prefix = "lock"
    elif result.mnemonic in ["rep", "repz", "repnz"]: result.prefix = result.mnemonic
    if t.len == 0:
      result.mnemonic = ""
      return
    sp = t.find(' ')
    if sp < 0: sp = t.len
    result.mnemonic = t[0 ..< sp]
    t = t.substr(sp).strip
  if result.mnemonic in JccMnemonics:
    # "401b60 <name+0x40>" or "401b60 <name>"
    let lb = t.find(" <")
    var addrTxt = t
    if lb >= 0:
      addrTxt = t[0 ..< lb]
      let rb = t.rfind('>')
      if rb > lb: result.targetSym = t[lb+2 ..< rb]
    if isHex(addrTxt.strip):
      result.target = parseHex(addrTxt.strip)
      return
  if t.len > 0:
    for part in t.split(','):
      result.ops.add parseOperandText(part.strip)

# -------------------------------------------------------------- translation

type
  Issue = object
    cat: string             ## histogram key: what capability is missing
    detail: string
    address: int64

  TransCtx = object
    info: ElfInfo
    env: ptr SpliceEnv        ## nil for translate/audit; set in splice mode,
                              ## where names resolve instead of raising issues
    labels: Table[int64, string]
    lines: seq[string]
    issues: seq[Issue]
    funcLo, funcHi: int64
    flagsLiveNow: bool        ## EFLAGS are read after the current instruction
                              ## before being rewritten — a lowering that uses
                              ## ALU ops (lea-with-index) must not run then
    zeroXmm: HashSet[string]  ## xmm registers currently known to hold zero
                              ## (after `pxor x,x`) — a 16B store of one is
                              ## re-expressed as two 8-byte zero stores
    tpRegs: HashSet[string]   ## registers holding the THREAD POINTER (after
                              ## `mov r, fs:0x0`). In the native ELF that value
                              ## is &arkham.tls.0 — a link-time symbol — so the
                              ## read becomes a lea, and `[r ± tpoff]` accesses
                              ## remap to the native tvar SYMBOLS (the offsets
                              ## differ between the two TLS layouts!)

proc issue(c: var TransCtx; cat, detail: string; address: int64) =
  c.issues.add Issue(cat: cat, detail: detail, address: address)

proc emit(c: var TransCtx; s: string) =
  c.lines.add s

const
  # Straight pass-through: same tag name, same operand order, no width games
  # needed at 64 bits. Membership in x64InstTags is still checked at use.
  Passthrough64 = ["add", "sub", "and", "or", "xor", "cmp", "test", "imul",
                   "shl", "shr", "sar", "sal", "rol", "ror", "inc", "dec",
                   "neg", "not", "bsf", "bsr", "bt", "bts", "btr", "btc",
                   "bswap", "popcnt", "xchg", "cmpxchg", "xadd",
                   "movsd", "movss", "movapd", "movdqu", "addsd", "subsd",
                   "mulsd", "divsd", "addss", "subss", "mulss", "divss",
                   "cvtsi2sd", "cvtsi2ss", "cvttsd2si", "cvttss2si",
                   "cvtsd2ss", "cvtss2sd", "comisd", "comiss",
                   "punpcklqdq", "push", "pop"]

proc gccRegToNif(r: string): string = "(" & r & ")"

proc typeForBits(bits: int; signed = false): string =
  if signed: "(i " & $bits & ")" else: "(u " & $bits & ")"

proc memToNif(c: var TransCtx; op: IOperand; address: int64;
              wantBits: int): tuple[ok: bool; text: string] =
  ## Render a memory operand. `wantBits` sizes the access (0 = 64-bit word).
  if c.env != nil and op.base in c.tpRegs and op.seg.len == 0:
    # `[tp + tpoff]` ≡ `fs:[tpoff]` ≡ the tvar symbol — but ONLY symbolically:
    # gcc's tpoff and the native TLS block's offsets are different layouts.
    if op.index.len > 0:
      c.issue("tls-tp-index", op.text, address)
      return (false, "")
    let (sym, delta) = tlsSymbolFor(c.info, op.disp)
    if sym.len == 0:
      c.issue("tls-tp-unmapped", op.text, address)
      return (false, "")
    if delta != 0:
      c.issue("tls-interior", sym & "+" & $delta, address)
      return (false, "")
    if gccKey(sym) in c.env.data:
      return (true, dataSpelling(c.env[], gccKey(sym)))
    c.issue("tls-no-native", sym, address)
    return (false, "")
  if op.seg == "fs":
    if op.disp == 0 and op.base == "" and op.index == "":
      # `mov reg, fs:0x0` reads the thread pointer — gcc's address-of-TLS-var
      # idiom (a following lea adds the variable's offset). Resolving it means
      # pairing the two instructions; splice-stage work.
      c.issue("tls-threadptr", op.text, address)
      return (false, "")
    let (sym, delta) = tlsSymbolFor(c.info, op.disp)
    if sym.len == 0:
      c.issue("tls-unmapped", "fs:" & $op.disp, address)
      return (false, "")
    if c.env != nil:
      if delta != 0:
        # A field of a TLS aggregate would need the native field spelling.
        c.issue("tls-interior", sym & "+" & $delta, address)
        return (false, "")
      if gccKey(sym) in c.env.data:
        # A tvar SYMBOL is the whole fs-relative access in asm-NIF.
        return (true, dataSpelling(c.env[], gccKey(sym)))
      c.issue("tls-no-native", sym, address)
      return (false, "")
    let spelled = if delta == 0: sym else: sym & "+" & $delta
    c.issue("tls-name-map", spelled & " needs its native tvar symbol", address)
    return (true, spelled)
  if op.seg.len > 0:
    c.issue("segment-" & op.seg, op.text, address)
    return (false, "")
  if op.base == "rip":
    let target = op.ripTarget
    let sym = if target >= 0: symbolAt(c.info, target) else: ""
    if sym.len == 0:
      c.issue("rodata-anon", "rip target 0x" & target.toHex, address)
      return (false, "")
    if c.env != nil:
      if gccKey(sym) in c.env.data:
        return (true, dataSpelling(c.env[], gccKey(sym)))
      c.issue("global-no-native", sym, address)
      return (false, "")
    c.issue("global-name-map", sym & " needs its native symbol", address)
    return (true, sym)
  if op.base == "" and op.index == "":
    c.issue("absolute-mem", op.text, address)
    return (false, "")
  var inner: string
  if op.index.len > 0:
    # `(mem base index scale [disp])` with a raw register index — accepted by
    # nifasm since 2026-08-16 (this tool's first audit motivated it).
    if op.base.len == 0:
      c.issue("mem-no-base", op.text, address)
      return (false, "")
    inner = "(mem " & gccRegToNif(op.base) & " " & gccRegToNif(op.index) &
            " " & $op.scale & (if op.disp != 0: " " & $op.disp else: "") & ")"
  else:
    inner = "(mem " & gccRegToNif(op.base) &
            (if op.disp != 0: " " & $op.disp else: "") & ")"
  if wantBits notin [0, 64, 128]:
    # 128-bit accesses (movdqu & friends) are inherently 16 bytes — the mem
    # operand's scalar type is not consulted, so no cast is needed there.
    result = (true, "(cast " & typeForBits(wantBits) & " " & inner & ")")
  else:
    result = (true, inner)

proc opToNif(c: var TransCtx; op: IOperand; address: int64;
             wantBits = 0): tuple[ok: bool; text: string] =
  case op.kind
  of opReg, opXmm:
    result = (true, gccRegToNif(op.reg))
  of opImm:
    result = (true, $op.imm)
  of opMem:
    result = memToNif(c, op, address, if wantBits != 0: wantBits else: op.bits)
  else:
    c.issue("operand-parse", op.text, address)
    result = (false, "")

proc widthOf(ins: Insn): int =
  ## The instruction's operation width: widest register operand, else the
  ## memory operand's size prefix.
  result = 0
  for op in ins.ops:
    if op.kind == opReg:
      result = max(result, op.bits)
  if result == 0:
    for op in ins.ops:
      if op.kind == opMem and op.bits > 0:
        result = op.bits

proc readsFlags(m: string): bool =
  (m[0] == 'j' and m != "jmp") or m.startsWith("set") or
    m.startsWith("cmov") or m in ["adc", "sbb", "rcl", "rcr"]

proc writesFlags(m: string): bool =
  m in ["add", "sub", "and", "or", "xor", "cmp", "test", "neg", "shl", "shr",
        "sar", "sal", "inc", "dec", "imul", "mul", "div", "idiv", "bsf", "bsr",
        "bt", "bts", "btr", "btc", "popcnt", "cmpxchg", "xadd",
        "comisd", "comiss", "ucomisd", "ucomiss"]

proc flagsLiveAfter(insns: seq[Insn]; i: int): bool =
  ## Linear approximation: a reader before the next writer means live.
  ## Flags never survive a call/ret and practically never an unconditional
  ## jmp (gcc re-tests at the join).
  for j in i + 1 ..< insns.len:
    let m = insns[j].mnemonic
    if m.len == 0: continue
    if readsFlags(m): return true
    if writesFlags(m) or m in ["call", "jmp", "ret"]: return false
  result = false

const
  ShiftMnemonics = ["shl", "shr", "sar", "sal", "rol", "ror"]
  ## The ALU family nifasm's cast-typed sub-width register operands cover
  ## (2026-08-16): `(add (cast (u 32) (rax)) …)` runs the op at that width.
  WiredSubWidth = ["add", "sub", "and", "or", "xor", "cmp", "test", "imul",
                   "shl", "shr", "sar", "neg", "not", "bt", "bts", "btr", "btc"]

proc regOperandToNif(op: IOperand): string =
  ## A sub-width register operand spells its width as an explicit cast.
  if op.kind == opReg and op.bits in [8, 16, 32]:
    "(cast (u " & $op.bits & ") " & gccRegToNif(op.reg) & ")"
  else:
    gccRegToNif(op.reg)

proc translateAlu(c: var TransCtx; ins: Insn) =
  ## Shared ALU/data path. Sub-width semantics are the load-bearing question:
  ## a MEMORY operand carries its width in its type (nifasm sizes the access
  ## from it — exact), but a sub-64-bit REGISTER operand has no spelling in
  ## the model yet, so those become the `aluN-…` histogram entries.
  let m = ins.mnemonic
  template unsupported(cat: string) =
    c.issue(cat, ins.raw.strip, ins.address)
    c.emit "  (!" & cat & " ; " & ins.raw.strip & ")"
    return
  if m notin x64InstTags:
    unsupported("no-tag-" & m)
  for op in ins.ops:
    if op.kind == opReg and op.high8:
      unsupported("high8-" & m)   # ah/bh/ch/dh have no canonical-reg spelling
  if m == "imul" and ins.ops.len == 3 and ins.ops[2].kind != opImm:
    unsupported("imul3-form")
  var regW = 0
  var memW = 0
  let opsEnd = if m in ShiftMnemonics: 1 else: ins.ops.len
  for i in 0 ..< opsEnd:
    if ins.ops[i].kind == opReg: regW = max(regW, ins.ops[i].bits)
    elif ins.ops[i].kind == opMem: memW = max(memW, ins.ops[i].bits)
  var subWidth = false
  if regW in [8, 16, 32] and m notin ["push", "pop"]:
    # Sub-width shapes, all expressible since 2026-08-16:
    #  * mem-DEST + reg source: the mem operand's cast type sizes the access
    #    (sized MR emitters);
    #  * reg-DEST: the register spells its width as an explicit cast — with a
    #    reg, imm, or same-width mem source (sized RM emitters);
    #  * reg-reg / reg-imm: both via the cast spelling.
    if memW == regW and m in ["add", "sub", "and", "or", "xor", "cmp", "test"]:
      if ins.ops[0].kind == opReg:
        if m == "test":
          unsupported("test-reg-mem")    # no sized reg-dest TEST-with-mem form
        subWidth = true                  # reg-dest: cast the register side
      # mem-dest: the mem operand's own cast type sizes it
    elif memW != 0:
      unsupported("alu" & $regW & "-mem-" & m)
    elif m in WiredSubWidth:
      subWidth = true
    else:
      unsupported("alu" & $regW & "-" & m)
  if m in ShiftMnemonics and ins.ops.len == 2 and ins.ops[1].kind == opReg and
     ins.ops[1].reg != "rcx":
    unsupported("shift-count-" & ins.ops[1].reg)
  if m in ["rol", "ror"] and ins.ops.len == 2 and ins.ops[1].kind == opReg and
     ins.ops[1].reg != "rcx":
    unsupported("rotate-count-" & ins.ops[1].reg)
  if m in ["xchg", "cmpxchg", "xadd"] and ins.prefix == "lock" and
     ins.ops.len == 2 and ins.ops[1].kind == opImm:
    unsupported("atomic-imm")  # the exchange family takes register sources only
  var parts: seq[string] = @[]
  var allOk = true
  for i, op in ins.ops:
    if op.kind == opReg:
      # The shift COUNT is CL, spelled as the raw register; everything else
      # sub-width becomes a width cast.
      if subWidth and not (m in ShiftMnemonics and i == 1):
        parts.add regOperandToNif(op)
      else:
        parts.add gccRegToNif(op.reg)
    else:
      let (ok, s) = opToNif(c, op, ins.address)
      if not ok: allOk = false
      parts.add s
  if allOk:
    let body = "(" & m & " " & parts.join(" ") & ")"
    c.emit "  " & (if ins.prefix == "lock": "(lock " & body & ")" else: body)

proc emitCallGlue(c: var TransCtx; ins: Insn; tail: bool) =
  ## Splice mode. The spliced proc carries the `(lenient)` pragma, so a bare
  ## `(call P)` / tail `(jmp P)` suffices — arkham's ABI is plain SysV, so the
  ## gcc code's argument registers line up as-is; only the NAME needs mapping.
  let key = ins.targetSym
  template bail(cat: string) =
    c.issue(cat, ins.raw.strip, ins.address)
    c.emit "  (!" & cat & " ; " & ins.raw.strip & ")"
    return
  var spelling = ""
  if key.endsWith("@plt") and
     key[0 ..< key.len-4] in ["memcpy", "memset", "memcmp", "strlen"]:
    # gcc SYNTHESIZES these even in freestanding code; the native ELF is
    # libc-free, so the splice links a tiny `gccrt` module providing them.
    c.env.usedGccrt = true
    spelling = key[0 ..< key.len-4] & ".0.gccrt"
  elif "@" in key or "." in key:
    bail("extern-call")                    # @plt / .constprop-style clones
  elif key notin c.env.procs:
    bail("call-no-native")
  else:
    if key in c.env.dwarf:
      let (np, hr) = c.env.dwarf[key]
      let sig = c.env.procs[key]
      if np != sig.params.len or hr != sig.hasResult:
        bail("callee-overload")            # equal name, different overload
    spelling = procSpelling(c.env[], key)
  # A tail jump MUST become call+ret here, not `(jmp)`: the preserve contract
  # obliges this proc to restore the param registers before returning, but a
  # tail-callee needs its ARGUMENTS in those same registers — restoring before
  # the jmp destroys the arguments, and after it is too late. call+ret orders
  # it correctly: args intact for the call, contract registers restored by the
  # pops the `(ret)` line receives, then return.
  c.emit "  (call " & spelling & ")"
  if tail:
    c.emit "  (ret)"

proc translateInsn(c: var TransCtx; ins: Insn) =
  let m = ins.mnemonic
  template unsupported(cat: string) =
    c.issue(cat, ins.raw.strip, ins.address)
    c.emit "  (!" & cat & " ; " & ins.raw.strip & ")"
    return

  if m in DropMnemonics or m.startsWith("nop"):
    return

  # --- control flow -------------------------------------------------------
  if m == "call" and ins.target < 0:
    if c.env != nil and ins.ops.len == 1 and ins.ops[0].kind == opMem and
       ins.ops[0].base == "rip" and ins.ops[0].ripTarget >= 0:
      # An indirect call through a GLOBAL function pointer — nifasm's lenient
      # bare `(call G)` on a gvar emits the load-and-call-through-rax lowering.
      let sym = symbolAt(c.info, ins.ops[0].ripTarget)
      if sym.len > 0 and gccKey(sym) in c.env.data:
        c.emit "  (call " & dataSpelling(c.env[], gccKey(sym)) & ")"
        return
    unsupported("call-indirect")
  if m == "jmp" and ins.target < 0:
    unsupported("jmp-indirect")
  if ins.target >= 0:
    if m == "call":
      if c.env != nil:
        emitCallGlue(c, ins, tail = false)
        return
      # A native call needs the callee's asm-NIF signature and a `(prepare …)`
      # around it; the callee name also needs gcc→native mapping. All of that
      # is splice-stage work — record what would be needed.
      c.issue("call", ins.targetSym, ins.address)
      c.emit "  (!call " & ins.targetSym & ")"
      return
    if ins.target >= c.funcLo and (c.funcHi < 0 or ins.target < c.funcHi):
      if m in x64InstTags:
        c.emit "  (" & m & " " & c.labels[ins.target] & ")"
      else:
        unsupported("jcc-" & m)
    else:
      if c.env != nil:
        # A tail jump IS a call in tail position: `call F; ret` is
        # semantically identical (at the cost of one extra frame).
        emitCallGlue(c, ins, tail = true)
        return
      c.issue("tail-jump", ins.targetSym, ins.address)
      c.emit "  (!tailjmp " & ins.targetSym & ")"
    return

  case m
  of "ret":
    c.emit "  (ret)"
  of "leave":
    c.emit "  (mov (rsp) (rbp))"
    c.emit "  (pop (rbp))"
  of "cdqe":
    c.emit "  (movsx (rax) (rax) 32)"
  of "cdq", "cqo":
    # Belongs to the following idiv/div; nifasm's 3-operand (idiv D S R)
    # owns rdx itself, so the sign-extend marker is folded away.
    discard
  of "movabs":
    let (ok, dst) = opToNif(c, ins.ops[0], ins.address)
    if ok: c.emit "  (mov " & dst & " " & $ins.ops[1].imm & ")"
  of "mov":
    let w = widthOf(ins)
    let dst = ins.ops[0]
    let src = ins.ops[1]
    if (dst.kind == opReg and dst.high8) or (src.kind == opReg and src.high8):
      unsupported("mov-high8")
    if c.env != nil and dst.kind == opReg and w == 64 and src.kind == opMem and
       src.seg == "fs" and src.disp == 0 and src.base.len == 0 and
       src.index.len == 0:
      # The thread-pointer read (`mov r, fs:0x0` — glibc keeps the TCB
      # self-pointer at fs:[0]). The native thread pointer IS &arkham.tls.0,
      # a link-time symbol, so materialize it directly.
      c.emit "  (lea " & gccRegToNif(dst.reg) & " arkham.tls.0)"
      c.tpRegs.incl dst.reg
      return
    if c.env != nil and dst.kind == opReg and w == 64 and src.kind == opReg and
       src.reg in c.tpRegs:
      c.emit "  (mov " & gccRegToNif(dst.reg) & " " & gccRegToNif(src.reg) & ")"
      c.tpRegs.incl dst.reg
      return
    if dst.kind == opReg and w == 32:
      # 32-bit mov ZERO-EXTENDS into the 64-bit register.
      if src.kind == opImm:
        # Encode the zero-extended value so nifasm's imm materialization
        # can't sign-extend a negative imm32 the way `mov r64, imm` would.
        c.emit "  (mov " & gccRegToNif(dst.reg) & " " &
               $(cast[int64](cast[uint32](src.imm))) & ")"
      elif src.kind == opMem:
        # nifasm's sized load: a sub-width unsigned mem type zero-extends.
        let (ok, s) = opToNif(c, src, ins.address, 32)
        if ok: c.emit "  (mov " & gccRegToNif(dst.reg) & " " & s & ")"
      else:
        # reg-reg: movzx is the register-source zero-extension form.
        c.emit "  (movzx " & gccRegToNif(dst.reg) & " " &
               gccRegToNif(src.reg) & " 32)"
    elif dst.kind == opReg and w in [8, 16]:
      # Partial-register write (no zero-extend) — gcc emits these rarely and
      # only when the upper bits are dead; a full movzx is the safe rendering
      # only if nothing reads the merge, so flag it for review.
      unsupported("mov" & $w & "-partial")
    elif dst.kind == opMem:
      let (okD, d) = opToNif(c, dst, ins.address, w)
      let (okS, s) = opToNif(c, src, ins.address)
      if okD and okS: c.emit "  (mov " & d & " " & s & ")"
    else:
      let (okD, d) = opToNif(c, dst, ins.address)
      let (okS, s) = opToNif(c, src, ins.address, w)
      if okD and okS: c.emit "  (mov " & d & " " & s & ")"
  of "movzx", "movsx", "movsxd":
    let srcBits = if m == "movsxd": 32 else: ins.ops[1].bits
    let signed = m != "movzx"
    let d = gccRegToNif(ins.ops[0].reg)
    if ins.ops[1].kind == opMem:
      # nifasm's `(movzx/movsx D S N)` is register-source-only; a memory
      # source is the sized load — the mem type's width AND signedness pick
      # the zero- vs sign-extension.
      var src = ins.ops[1]
      let (ok, s) = memToNif(c, src, ins.address, 0)
      if ok:
        let ty = (if signed: "(i " else: "(u ") & $srcBits & ")"
        c.emit "  (mov " & d & " (cast " & ty & " " & s & "))"
    elif ins.ops[1].kind == opReg and ins.ops[1].high8:
      # `movzx r, ah` = (rax >> 8) & 0xff — lower via shift + zero-extend.
      # The shift SETS flags (movzx does not), so only when EFLAGS are dead;
      # the signed variant is not worth the extra ceremony.
      if signed or c.flagsLiveNow:
        unsupported("movzx-high8")
      if ins.ops[0].reg != ins.ops[1].reg:
        c.emit "  (mov " & d & " " & gccRegToNif(ins.ops[1].reg) & ")"
      c.emit "  (shr " & d & " 8)"
      c.emit "  (movzx " & d & " " & d & " 8)"
    elif ins.ops[1].kind == opReg:
      let tag = if signed: "movsx" else: "movzx"
      c.emit "  (" & tag & " " & d & " " & gccRegToNif(ins.ops[1].reg) &
             " " & $srcBits & ")"
    else:
      unsupported("movzx-operand")
  of "lea":
    # nifasm's lea forms: `(lea dest sym)` (RIP-relative) and
    # `(lea dest (base-reg) offset)` — flat operands, NO SIB index and no
    # 32-bit form. Everything else lowers to mov/shl/add — 32-bit finals
    # zero-extend exactly like `lea r32` does.
    if ins.ops[0].kind != opReg:
      unsupported("lea-operand")
    let leaBits = ins.ops[0].bits
    if leaBits notin [32, 64]:
      unsupported("lea" & $leaBits)
    let dreg = ins.ops[0].reg
    let d = gccRegToNif(dreg)
    let src = ins.ops[1]
    if src.kind != opMem:
      unsupported("lea-operand")
    if src.seg.len > 0:
      unsupported("lea-tls")
    elif c.env != nil and src.base in c.tpRegs:
      # `lea d, [tp + tpoff]` = &tvar — exactly arkham's own two-lea idiom:
      # nifasm resolves the tvar SYMBOL as the second lea's displacement, so
      # the native TLS layout's offset is used, not gcc's.
      if leaBits != 64 or src.index.len > 0:
        unsupported("tls-tp-lea")
      let (sym, delta) = tlsSymbolFor(c.info, src.disp)
      if sym.len == 0 or gccKey(sym) notin c.env.data:
        unsupported("tls-tp-lea")
      c.emit "  (lea " & d & " (" & src.base & ") " &
             dataSpelling(c.env[], gccKey(sym)) & ")"
      if delta != 0:
        c.emit "  (lea " & d & " (" & dreg & ") " & $delta & ")"
    elif src.base == "rip":
      if leaBits != 64:
        unsupported("lea32-rip")
      let sym = if src.ripTarget >= 0: symbolAt(c.info, src.ripTarget) else: ""
      if sym.len == 0:
        unsupported("rodata-anon")
      if c.env != nil:
        if gccKey(sym) in c.env.data:
          c.emit "  (lea " & d & " " & dataSpelling(c.env[], gccKey(sym)) & ")"
        else:
          unsupported("global-no-native")
      else:
        c.issue("global-name-map", sym & " needs its native symbol", ins.address)
        c.emit "  (lea " & d & " " & sym & ")"
    elif leaBits == 64 and src.index.len == 0 and src.base.len > 0:
      c.emit "  (lea " & d & " (" & src.base & ") " & $src.disp & ")"
    else:
      # The ALU lowering SETS flags while lea does not, so it is only sound
      # when EFLAGS are dead here.
      if c.flagsLiveNow:
        unsupported("lea-index-flags")
      let idx = src.index
      let sh = case src.scale
               of 1: 0
               of 2: 1
               of 4: 2
               else: 3
      let wdest = if leaBits == 32: "(cast (u 32) " & d & ")" else: d
      template mov(b: string) =
        c.emit "  (mov " & d & " " & gccRegToNif(b) & ")"
      template addReg(b: string) =
        c.emit "  (add " & wdest & " " & gccRegToNif(b) & ")"
      template addImm(v: int64) =
        if v != 0: c.emit "  (add " & wdest & " " & $v & ")"
      template shlImm() =
        if sh > 0: c.emit "  (shl " & wdest & " " & $sh & ")"
      template zext32IfPlainCopy(usedWidthOp: bool) =
        # a 32-bit lea that degenerated to a bare register copy still
        # zero-extends; a plain 64-bit mov would not
        if leaBits == 32 and not usedWidthOp:
          c.emit "  (movzx " & d & " " & d & " 32)"
      if src.base.len == 0:
        if dreg != idx: mov(idx)
        shlImm()
        addImm(src.disp)
        zext32IfPlainCopy(sh > 0 or src.disp != 0)
      elif src.index.len == 0:
        if dreg != src.base: mov(src.base)
        addImm(src.disp)
        zext32IfPlainCopy(src.disp != 0)
      elif dreg == src.base:
        if sh == 0 and dreg != idx:
          addReg(idx)
          addImm(src.disp)
        elif dreg == idx:
          # `lea r, [r + r*scale]` is just r * (scale+1) — 3-operand imul.
          c.emit "  (imul " & wdest & " " & d & " " & $(src.scale + 1) & ")"
          addImm(src.disp)
        else:
          unsupported("lea-index-alias")   # would need a scratch register
      else:
        if dreg != idx: mov(idx)
        shlImm()
        addReg(src.base)
        addImm(src.disp)
  of "movq", "movd":
    let tag = if m == "movq": "movfq" else: "movfd"
    let (okD, d) = opToNif(c, ins.ops[0], ins.address)
    let (okS, s) = opToNif(c, ins.ops[1], ins.address)
    if okD and okS: c.emit "  (" & tag & " " & d & " " & s & ")"
  of "ucomisd", "ucomiss":
    # Same EFLAGS as the ordered compare; they differ only in NaN exception
    # signalling, which this code does not use.
    let (okD, d) = opToNif(c, ins.ops[0], ins.address)
    let (okS, s) = opToNif(c, ins.ops[1], ins.address)
    if okD and okS: c.emit "  (" & m.substr(1) & " " & d & " " & s & ")"
  of "idiv", "div":
    # gcc: cqo/cdq + idiv S with implicit rdx:rax; nifasm's form is
    # `(idiv (rdx) (rax) src)` and it emits the sign-extending cqo ITSELF —
    # which is why the translator drops gcc's cdq/cqo above.
    if widthOf(ins) != 64:
      unsupported("div" & $widthOf(ins))
    let (okS, s) = opToNif(c, ins.ops[0], ins.address)
    if okS:
      c.emit "  (" & m & " (rdx) (rax) " & s & ")"
  of "mul":
    let (okS, s) = opToNif(c, ins.ops[0], ins.address)
    if okS: c.emit "  (mul " & s & ")"
  of "movs", "movsb", "movsw", "movsq", "stos", "stosb", "stosw", "stosd",
     "stosq", "scas", "lods":
    # Intel-syntax objdump prints "movs BYTE PTR es:[rdi],BYTE PTR ds:[rsi]".
    if ins.prefix.startsWith("rep") and m in ["movs", "movsb", "movsw", "movsq"]:
      let bits = if ins.ops.len > 0 and ins.ops[0].bits > 0: ins.ops[0].bits
                 elif m == "movsb": 8
                 elif m == "movsw": 16
                 elif m == "movsq": 64
                 else: 0
      let tag = case bits
                of 8: "repmovsb"
                of 16: "repmovsw"
                of 32: "repmovsd"
                of 64: "repmovsq"
                else: ""
      if tag in x64InstTags:
        c.emit "  (" & tag & ")"
      else:
        unsupported("rep-movs" & $bits)
    else:
      unsupported("string-" & ins.prefix & m)
  of "xor":
    if ins.ops.len == 2 and ins.ops[0].kind == opReg and
       ins.ops[1].kind == opReg and ins.ops[0].reg == ins.ops[1].reg:
      # The zeroing idiom — exact at every width (32-bit xor zero-extends).
      c.emit "  (mov " & gccRegToNif(ins.ops[0].reg) & " 0)"
    else:
      translateAlu(c, ins)
  of "xchg":
    if ins.ops.len == 2 and ins.ops[0].kind == opReg and
       ins.ops[1].kind == opReg and ins.ops[0].reg == ins.ops[1].reg:
      discard   # "xchg ax,ax" and friends: alignment padding
    else:
      translateAlu(c, ins)
  of "pxor", "xorps":
    if ins.ops.len == 2 and ins.ops[0].kind == opXmm and
       ins.ops[1].kind == opXmm and ins.ops[0].reg == ins.ops[1].reg:
      # The xmm ZEROING idiom: no code here — the fact is consumed by the
      # 16-byte store below, which then needs no xmm register at all.
      c.zeroXmm.incl ins.ops[0].reg
    else:
      unsupported("insn-" & m)
  of "movups", "movaps", "movdqa", "movdqu":
    let dst = ins.ops[0]
    let src = ins.ops[1]
    if src.kind == opXmm and dst.kind == opMem and src.reg in c.zeroXmm:
      # A 16-byte store of a known-zero xmm: two 8-byte zero stores, exact.
      var hi = dst
      hi.disp += 8
      let (ok1, s1) = memToNif(c, dst, ins.address, 0)
      let (ok2, s2) = memToNif(c, hi, ins.address, 0)
      if ok1 and ok2:
        c.emit "  (mov (cast (u 64) " & s1 & ") 0)"
        c.emit "  (mov (cast (u 64) " & s2 & ") 0)"
    else:
      if dst.kind == opXmm: c.zeroXmm.excl dst.reg
      # All three move 16 raw bytes; movdqu is the one tag the model has and
      # is exact for them (the aligned forms merely ASSERT alignment).
      let (okD, d) = opToNif(c, ins.ops[0], ins.address, 128)
      let (okS, s) = opToNif(c, ins.ops[1], ins.address, 128)
      if okD and okS: c.emit "  (movdqu " & d & " " & s & ")"
  else:
    if m in Passthrough64:
      translateAlu(c, ins)
    elif m.startsWith("set") and m in x64InstTags:
      let (ok, d) = opToNif(c, ins.ops[0], ins.address)
      if ok: c.emit "  (" & m & " " & d & ")"
    elif m.startsWith("cmov") and m in x64InstTags:
      if widthOf(ins) != 64:
        unsupported("cmov" & $widthOf(ins))
      let (okD, d) = opToNif(c, ins.ops[0], ins.address)
      let (okS, s) = opToNif(c, ins.ops[1], ins.address)
      if okD and okS: c.emit "  (" & m & " " & d & " " & s & ")"
    elif m in x64InstTags:
      # Tag exists but no translation rule yet — flag rather than guess.
      unsupported("rule-missing-" & m)
    else:
      unsupported("insn-" & m)

const InvertedJcc = {
  "je": "jne", "jne": "je", "jz": "jnz", "jnz": "jz",
  "jl": "jge", "jge": "jl", "jle": "jg", "jg": "jle",
  "jb": "jae", "jae": "jb", "jbe": "ja", "ja": "jbe",
  "js": "jns", "jns": "js", "jo": "jno", "jno": "jo",
  "jnge": "jge", "jnae": "jae", "jna": "ja", "jng": "jg"}.toTable

type
  LoopRegion = object
    start, endIdx: int        ## instruction-index span [header, last back-edge]
    header: int64             ## the header's address
    contLabel: string         ## "" until a mid-region back-jump needs it
    exitLabel: string         ## "" unless the final back-edge is conditional

proc translateFunc(fn: GccFunc; info: ElfInfo; env: ptr SpliceEnv = nil):
    tuple[nif: string; body: seq[string]; issues: seq[Issue]] =
  var insns: seq[Insn] = @[]
  for line in fn.lines:
    var ins = parseInsnLine(line)
    if ins.mnemonic.len == 0: continue
    # objdump prints the rip-relative resolution as a comment: "# 404040 <sym>"
    if ins.comment.len > 0:
      let p = ins.comment.splitWhitespace
      if p.len >= 1 and isHex(p[0]):
        for op in ins.ops.mitems:
          if op.kind == opMem and op.base == "rip":
            op.ripTarget = parseHex(p[0])
    insns.add ins
  var c = TransCtx(info: info, env: env, labels: initTable[int64, string](),
                   funcLo: fn.address,
                   funcHi: if insns.len > 0: insns[^1].address + 16 else: -1)
  # Local branch targets become labels.
  var labelN = 0
  for ins in insns:
    if ins.target >= c.funcLo and (c.funcHi < 0 or ins.target < c.funcHi) and
       ins.mnemonic != "call" and ins.target notin c.labels:
      # `.0` suffix: under the nominal-symbol rules a non-digit suffix would
      # read as a foreign-module qualifier ("L3.d" → module "d").
      c.labels[ins.target] = "L" & $labelN & ".0"
      inc labelN

  # nifasm's invariant is "every jmp is FORWARD; a back-edge is a (loop …)",
  # whose back-edge the assembler emits itself. gcc's loops are natural (the
  # source is structured), so each backward-jump target H spans a region
  # [H, last jump→H] that we wrap in `(loop (stmts …))`: a mid-region jump→H
  # becomes a forward `continue` to a label at the loop's bottom (falling into
  # the internal back-edge), and a CONDITIONAL final back-edge inverts into a
  # forward exit jump placed right after the loop.
  var addrIdx = initTable[int64, int]()
  for i, ins in insns: addrIdx[ins.address] = i

  # Cold-block inlining. gcc lays unlikely paths out of line at the function
  # tail, ending with a `jmp` BACK into the mainline — a backward jump that is
  # a LAYOUT artifact, not a loop, and would wreck the region nesting below.
  # When such a block has exactly one entry (a conditional jump from before
  # the resume point), inline it there: the entry inverts to skip the block,
  # and its exit jump becomes forward.
  # Splice mode emits `(lenient)` procs, where backward jumps are legal — the
  # whole control-flow recovery below (cold-block inlining, tail duplication,
  # loop regions) is only needed for the STRUCTURED translate/audit output.
  let structured = env == nil
  var relocEntry = initTable[int, (int, int)]()   # entry jcc idx → [start, end]
  var relocated = initHashSet[int]()
  for bi in 0 ..< insns.len:
    if not structured: break
    let bj = insns[bi]
    if bj.mnemonic != "jmp" or bj.target < 0 or bj.target notin addrIdx or
       addrIdx[bj.target] > bi:
      continue
    # the jump's block: back to the nearest label; must not be entered by
    # fallthrough (preceded by an unconditional terminator) and must have no
    # interior labels (single entry, single block)
    var s = bi
    while s > 0 and insns[s].address notin c.labels: dec s
    if s == 0 or insns[s].address notin c.labels: continue
    if insns[s-1].mnemonic notin ["jmp", "ret", "ud2"]: continue
    var ok = true
    for k in s + 1 .. bi:
      if insns[k].address in c.labels: ok = false
    if not ok: continue
    # Every entry must be inlinable: a conditional jump (inverted to skip the
    # inlined copy) or an unconditional jmp (replaced by the copy outright),
    # sitting in the mainline BEFORE the block, with the block's exit target
    # forward from there. A multi-entry block is DUPLICATED per entry — cold
    # paths are short, and gcc already paid the layout cost.
    var preds: seq[int] = @[]
    for k in 0 ..< insns.len:
      if insns[k].target == insns[s].address and k != bi: preds.add k
    if preds.len == 0: continue
    ok = true
    for e in preds:
      if insns[e].mnemonic != "jmp" and insns[e].mnemonic notin InvertedJcc:
        ok = false
      if e >= s or e in relocated or e in relocEntry: ok = false
      if insns[e].address >= bj.target: ok = false
    for k in s .. bi:
      if k in relocated or k in relocEntry: ok = false
    if not ok: continue
    for e in preds:
      relocEntry[e] = (s, bi)
    for k in s .. bi: relocated.incl k

  # Cross-jumped shared tails: gcc merges identical exit sequences and paths
  # JUMP BACKWARD into them (-fcrossjumping). Those are not loops either —
  # tail DUPLICATION restores forward-only flow by copying the short
  # straight-line tail at each backward jump site. Real loop headers lead
  # into branching code, so they never qualify — a natural discriminator.
  var tailDup = initTable[int, (int, int)]()      # jump idx → tail [t..k]
  for j in 0 ..< insns.len:
    if not structured: break
    if j in relocated: continue
    let bj = insns[j]
    if bj.target < 0 or bj.mnemonic == "call" or bj.target notin addrIdx:
      continue
    let t = addrIdx[bj.target]
    if t > j: continue
    if bj.mnemonic != "jmp" and bj.mnemonic notin InvertedJcc: continue
    var k = t
    var okDup = true
    while true:
      if k >= insns.len or k - t >= 12:
        okDup = false
        break
      let m2 = insns[k].mnemonic
      if m2 == "ret":
        break                                     # a real terminator
      if m2 == "jmp":
        if bj.target >= 0 and insns[k].target notin addrIdx:
          break                                   # tail-call out of the function
        if insns[k].target >= 0 and insns[k].target in addrIdx and
           addrIdx[insns[k].target] > j:
          break                                   # forward from the dup site
        okDup = false
        break
      if insns[k].target >= 0 and m2 != "call":
        okDup = false                             # a branch: not straight-line
        break
      inc k
    if okDup:
      tailDup[j] = (t, k)

  var regionOf = initTable[int64, LoopRegion]()   # header addr → region
  for i, ins in insns:
    if not structured: break
    if i in relocated: continue                   # inlined at their entry site
    if i in tailDup: continue                     # duplicated at the jump site
    if ins.target >= 0 and ins.mnemonic != "call" and ins.target in addrIdx and
       addrIdx[ins.target] <= i:
      let h = ins.target
      if h notin regionOf:
        regionOf[h] = LoopRegion(start: addrIdx[h], endIdx: i, header: h)
      else:
        regionOf[h].endIdx = max(regionOf[h].endIdx, i)
  var regions: seq[LoopRegion] = @[]
  for _, r in regionOf: regions.add r
  regions.sort proc(a, b: LoopRegion): int = a.start - b.start
  var reducible = true
  for i in 1 ..< regions.len:
    for j in 0 ..< i:
      let (a, b) = (regions[j], regions[i])
      if b.start <= a.endIdx and b.endIdx > a.endIdx:
        reducible = false                      # overlap without nesting
  if not reducible:
    if getEnv("DISTILL_DBG").len > 0:
      stderr.writeLine "== " & fn.name & " regions:"
      for r in regions:
        stderr.writeLine "   [" & insns[r.start].address.hexStr & " .. " &
                         insns[r.endIdx].address.hexStr & "]"
      stderr.writeLine "   relocated blocks: " & $relocEntry.len
      for e, (s, bi) in relocEntry:
        stderr.writeLine "   entry@" & insns[e].address.hexStr & " → [" &
                         insns[s].address.hexStr & ".." & insns[bi].address.hexStr & "]"
    c.issue("irreducible-cf", fn.name, fn.address)
    regions = @[]

  var open: seq[int] = @[]                     # indices into `regions`, innermost last
  var freshN = 0
  var emitInlined: proc(i: int) = nil
  emitInlined = proc(i: int) =
    ## Emit one instruction of a RELOCATED cold block at its inline position.
    ## Jumps that were backward in the original layout are forward here, so
    ## they emit directly; a nested cold-block entry recurses.
    let ins2 = insns[i]
    c.flagsLiveNow = flagsLiveAfter(insns, i)
    if i in relocEntry:
      let (s, e2) = relocEntry[i]
      if ins2.mnemonic == "jmp":
        # an unconditional entry: the inlined copy simply replaces the jmp
        for k in s .. e2: emitInlined(k)
      else:
        let ft = "Lf" & $freshN & ".0"
        inc freshN
        c.emit "  (" & InvertedJcc[ins2.mnemonic] & " " & ft & ")"
        for k in s .. e2: emitInlined(k)
        c.emit "  (lab :" & ft & ")"
    elif ins2.target >= 0 and ins2.mnemonic != "call" and
         ins2.target in c.labels and ins2.mnemonic in x64InstTags:
      c.emit "  (" & ins2.mnemonic & " " & c.labels[ins2.target] & ")"
    else:
      translateInsn(c, ins2)
  for i, ins in insns:
    if i in relocated: continue                # emitted at their entry site
    c.flagsLiveNow = flagsLiveAfter(insns, i)
    # Thread-pointer tracking: any write to a register drops the fact (the
    # tp-defining/propagating movs re-add it inside translateInsn, which runs
    # after this), and a call clobbers every volatile.
    if ins.ops.len > 0 and ins.ops[0].kind == opReg and
       ins.mnemonic notin ["cmp", "test", "push"] and ins.mnemonic[0] != 'j':
      c.tpRegs.excl ins.ops[0].reg
    if ins.mnemonic == "call":
      for r in ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]:
        c.tpRegs.excl r
    for ri, r in regions:
      if r.start == i:
        c.emit "  (loop (stmts"
        open.add ri
    if ins.address in c.labels:
      c.zeroXmm.clear()                        # zero-xmm facts don't cross joins
      c.emit "  (lab :" & c.labels[ins.address] & ")"
    # A jump back to an open loop header is rewritten; everything else keeps
    # its ordinary translation.
    var handled = false
    if i in relocEntry:
      emitInlined(i)
      handled = true
    elif i in tailDup:
      let (t, k) = tailDup[i]
      if ins.mnemonic == "jmp":
        for x in t .. k: emitInlined(x)
      else:
        let ft = "Lt" & $freshN & ".0"
        inc freshN
        c.emit "  (" & InvertedJcc[ins.mnemonic] & " " & ft & ")"
        for x in t .. k: emitInlined(x)
        c.emit "  (lab :" & ft & ")"
      handled = true
    elif ins.target >= 0 and ins.mnemonic != "call" and ins.target in addrIdx and
       addrIdx[ins.target] <= i and regions.len > 0:
      var ri = -1
      for o in open:
        if regions[o].header == ins.target: ri = o
      if ri < 0:
        c.issue("backedge-crossing", ins.raw.strip, ins.address)
        c.emit "  (!backedge " & ins.raw.strip & ")"
        handled = true
      elif i == regions[ri].endIdx:
        if ins.mnemonic == "jmp":
          discard                              # the (loop) supplies the back-edge
        elif ins.mnemonic in InvertedJcc:
          if regions[ri].exitLabel.len == 0:
            regions[ri].exitLabel = "Lx" & $freshN & ".0"
            inc freshN
          c.emit "  (" & InvertedJcc[ins.mnemonic] & " " &
                 regions[ri].exitLabel & ")"
        else:
          c.issue("backedge-invert-" & ins.mnemonic, ins.raw.strip, ins.address)
          c.emit "  (!backedge " & ins.raw.strip & ")"
        handled = true
      else:                                    # a `continue` to the header
        if regions[ri].contLabel.len == 0:
          regions[ri].contLabel = "Lc" & $freshN & ".0"
          inc freshN
        c.emit "  (" & ins.mnemonic & " " & regions[ri].contLabel & ")"
        handled = true
    if not handled:
      translateInsn(c, ins)
    for oi in countdown(open.len - 1, 0):
      let ri = open[oi]
      if regions[ri].endIdx == i:
        if regions[ri].contLabel.len > 0:
          c.emit "  (lab :" & regions[ri].contLabel & ")"
        c.emit "  ))"
        if regions[ri].exitLabel.len > 0:
          c.emit "  (lab :" & regions[ri].exitLabel & ")"
        open.delete oi
  result.body = c.lines
  result.issues = c.issues
  result.nif = "(proc :" & fn.name & ".0\n (params)\n (result)\n (clobber)\n" &
               " (stmts\n" & c.lines.join("\n") & "\n ))\n"

# ------------------------------------------------------------------ reports

proc issueHistogram(issues: seq[Issue]): seq[(string, int, string)] =
  ## (category, count, one example detail), most frequent first.
  var h = initCountTable[string]()
  var example = initTable[string, string]()
  for i in issues:
    h.inc i.cat
    if i.cat notin example: example[i.cat] = i.detail
  result = @[]
  for k, v in h: result.add (k, v, example[k])
  result.sort proc(a, b: (string, int, string)): int = b[1] - a[1]

const
  ## Issues that are name-resolution work for the SPLICE stage, not missing
  ## nifasm/instructions.md capability — reported separately.
  SpliceStageCats = ["call", "tail-jump", "tls-name-map", "global-name-map",
                     "lea-mem"]

proc isCapabilityGap(cat: string): bool =
  cat notin SpliceStageCats

proc isRuntimeGlue(name: string): bool =
  ## crt/libc scaffolding that would never be spliced.
  name.endsWith("@plt") or name.startsWith("__") or
    name in ["_init", "_fini", "_start", "init", "frame_dummy",
             "register_tm_clones", "deregister_tm_clones", "_dl_relocate_static_pie"]

# --------------------------------------------------------------------- main

proc outDir(): string =
  result = repoDir() / "listings"
  createDir result

proc cmdCompare(src: string; funcSubs: seq[string]) =
  let work = outDir() / ".distillator.work"
  removeDir work
  createDir work
  let base = src.extractFilename.changeFileExt("")
  echo "workload : ", src
  echo "native   : nimony n --opt:speed  (arkham + nifasm)"
  echo "gcc      : nimony c --opt:speed --passC:-O3\n"
  let (elf, spans) = buildNative(src, work)
  let (natFull, natInsns) = disasmNative(elf, spans)
  let gccExe = buildGcc(src, work, @[])
  let (gccFull, gccFuncs) = disasmGcc(gccExe)
  writeFile(outDir() / base & ".arkham.s", natFull)
  writeFile(outDir() / base & ".gcc.s", gccFull)

  proc countIns(lines: seq[string]): (int, int) =
    var addrs: seq[int64] = @[]
    for l in lines:
      let t = l.strip
      let colon = t.find(':')
      if colon > 0 and isHex(t[0 ..< colon]): addrs.add parseHex(t[0 ..< colon])
    result = (lines.len, if addrs.len >= 2: int(addrs[^1] - addrs[0]) else: 0)

  echo alignLeft("function", 22), align("arkham (ins/byte)", 18), " ",
       align("gcc -O3 (ins/byte)", 19), align("ratio ins", 10)
  echo repeat('-', 70)
  for sub in funcSubs:
    var natLines: seq[string] = @[]
    for sp in spans:
      if sub in sp.name:
        natLines = sliceNative(natInsns, sp)
        writeFile(outDir() / sub & ".arkham.s",
                  sp.name & ":\n" & natLines.join("\n") & "\n")
        break
    var gccLines: seq[string] = @[]
    for fn in gccFuncs:
      if sub in fn.name:
        gccLines = fn.lines
        writeFile(outDir() / sub & ".gcc.s",
                  fn.name & ":\n" & gccLines.join("\n") & "\n")
        break
    let (ni, nb) = countIns(natLines)
    let (gi, gb) = countIns(gccLines)
    let ratio = if gi > 0: formatFloat(ni / gi, ffDecimal, 2) & "x" else: "-"
    echo alignLeft(sub, 22), align($ni & " /" & $nb, 18), " ",
         align($gi & " /" & $gb, 19), align(ratio, 10)
  echo "\nlistings written to ", outDir()
  removeDir work

proc cmdTranslate(src: string; funcSubs: seq[string]; audit: bool) =
  let work = outDir() / ".distillator.work"
  removeDir work
  createDir work
  # Jump tables would need label addresses baked into rodata — outside the
  # model on purpose; asking gcc not to emit them keeps switches expressible.
  # -no-pie + local-exec TLS mirror the SPLICE TARGET (a static, libc-free
  # nifasm ELF): every TLS access becomes a direct fs:offset that maps to a
  # tvar symbol, and calls skip the PLT indirection a PIE build inserts.
  let gccExe = buildGcc(src, work, GccSpliceFlags)
  let (_, gccFuncs) = disasmGcc(gccExe)
  let info = readElfInfo(gccExe)

  var all: seq[Issue] = @[]
  var perFunc: seq[(string, int, int)] = @[]   # name, insns, capability gaps
  for fn in gccFuncs:
    if not audit:
      var hit = false
      for sub in funcSubs:
        if sub in fn.name: hit = true
      if not hit: continue
    if fn.lines.len == 0: continue
    let (nif, _, issues) = translateFunc(fn, info)
    var gaps = 0
    for i in issues:
      if isCapabilityGap(i.cat): inc gaps
    perFunc.add (fn.name, fn.lines.len, gaps)
    all.add issues
    if not audit:
      writeFile(outDir() / fn.name & ".asm.nif", nif)
      var rep: seq[string] = @[]
      rep.add "translation report for " & fn.name & " (" & $fn.lines.len &
              " instructions, " & $issues.len & " issues)"
      rep.add ""
      for i in issues:
        rep.add align(i.cat, 22) & "  " & i.detail &
                "   @0x" & i.address.hexStr
      writeFile(outDir() / fn.name & ".report.txt", rep.join("\n") & "\n")
      echo fn.name, ": ", fn.lines.len, " insns, ", issues.len, " issues → ",
           outDir() / fn.name & ".asm.nif"

  if not audit and perFunc.len == 0:
    echo "no function matched ", funcSubs.join("/"),
         " — likely inlined away at -O3; `distillator audit` lists what exists"
  if audit:
    var clean = 0
    for (_, _, gaps) in perFunc:
      if gaps == 0: inc clean
    echo "audited ", perFunc.len, " functions (",
         foldl(perFunc, a + b[1], 0), " instructions)"
    echo clean, " functions have NO capability gaps (only splice-stage work)\n"
    echo "capability gaps (missing instructions.md/nifasm forms):"
    for (cat, n, ex) in issueHistogram(all.filterIt(isCapabilityGap(it.cat))):
      echo align($n, 7), "  ", alignLeft(cat, 18), "  e.g. ", ex
    echo "\nsplice-stage work (name mapping / call glue, not model gaps):"
    for (cat, n, ex) in issueHistogram(all.filterIt(not isCapabilityGap(it.cat))):
      echo align($n, 7), "  ", alignLeft(cat, 18), "  e.g. ", ex
    echo "\nworkload functions ranked by capability gaps (crt/libc glue omitted):"
    perFunc.sort proc(a, b: (string, int, int)): int = a[2] - b[2]
    for (name, n, gaps) in perFunc:
      if isRuntimeGlue(name): continue
      echo align($gaps, 7), " gaps  ", align($n, 5), " insns  ", name
  removeDir work

# ------------------------------------------------------------------- splice

proc rspSlot(off: int): string =
  if off == 0: "(mem (rsp))" else: "(mem (rsp) " & $off & ")"

proc spliceGlueBody(body: seq[string]; sig: NativeProc): string =
  ## Wrap a translated gcc body so it honors the arkham proc's CONTRACT:
  ## nifasm treats only the declared `(clobber …)` registers as destroyed by a
  ## call, so every other SysV-volatile must be preserved around the gcc code
  ## (which assumes it may trash all of them). r11 additionally needs its
  ## typed-binding spelling — a raw `(r11)` operand is rejected (the staging
  ## bridge rule), so the body's r11 uses are renamed to a `rebind` name.
  ## The `(lenient)` pragma makes raw registers (params, r11) legal, so no
  ## rebinding or renaming is needed — only the machine-level CONTRACT glue
  ## remains: preserve every SysV-volatile the header doesn't declare
  ## clobbered (nifasm's callers may keep values there across the call).
  let lines = body
  const Vol = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]
  var preserved: seq[string] = @[]
  for r in Vol:
    if r notin sig.clobbers and not (sig.hasResult and r in sig.resultRegs):
      preserved.add r
  # Keep the push count EVEN so the callee-entry rsp stays ≡ 8 (mod 16) for
  # any calls inside the body (gcc may rely on the SysV alignment).
  if preserved.len mod 2 == 1: preserved.add preserved[^1]
  # The xmm counterpart: SysV says ALL xmm registers are call-clobbered, so the
  # gcc body trashes them freely — but nifasm callers only treat the header's
  # declared clobbers as destroyed and may keep values live in xmm registers
  # across the call. There is no xmm push, so the glue allocates a 16-byte slot
  # per used register instead (16*n keeps the rsp alignment parity intact).
  var xmms: seq[string] = @[]
  for l in lines:
    var i = 0
    while true:
      i = l.find("(xmm", i)
      if i < 0: break
      var j = i + 4
      while j < l.len and l[j] in {'0'..'9'}: inc j
      let r = l[i+1 ..< j]
      if j < l.len and l[j] == ')' and j > i + 4 and
         r notin xmms and r notin sig.clobbers:
        xmms.add r
      i = j
  xmms.sort proc(a, b: string): int =
    parseInt(a.substr(3)) - parseInt(b.substr(3))
  let area = 16 * xmms.len
  var outLines: seq[string] = @[]
  for r in preserved:
    outLines.add "  (push (" & r & "))"
  if area > 0:
    outLines.add "  (sub (rsp) " & $area & ")"
    for k, r in xmms:
      outLines.add "  (movdqu " & rspSlot(16 * k) & " (" & r & "))"
  for l in lines:
    if l.strip == "(ret)":
      if area > 0:
        for k in countdown(xmms.len - 1, 0):
          outLines.add "  (movdqu (" & xmms[k] & ") " & rspSlot(16 * k) & ")"
        outLines.add "  (add (rsp) " & $area & ")"
      for k in countdown(preserved.len - 1, 0):
        outLines.add "  (pop (" & preserved[k] & "))"
      outLines.add "  (ret)"
    else:
      outLines.add l
  result = "(lenient)\n  (stmts\n" & outLines.join("\n") & "\n )"

const GccRtModule = """(.nif27)
(stmts
 (proc :memcpy.0.
  (params)
  (result)
  (clobber)
  (lenient)
  (stmts
   (mov (rax) (rdi))
   (mov (rcx) (rdx))
   (repmovsb)
   (ret)))
 (proc :memset.0.
  (params)
  (result)
  (clobber)
  (lenient)
  (stmts
   (mov (rax) (rdi))
   (mov (rcx) 0)
   (lab :top.0)
   (cmp (rcx) (rdx))
   (je done.0)
   (mov (cast (u 8) (mem (rdi) (rcx) 1)) (rsi))
   (add (rcx) 1)
   (jmp top.0)
   (lab :done.0)
   (ret)))
 (proc :memcmp.0.
  (params)
  (result)
  (clobber)
  (lenient)
  (stmts
   (mov (rcx) 0)
   (lab :top.0)
   (cmp (rcx) (rdx))
   (je eq.0)
   (mov (r8) (cast (u 8) (mem (rdi) (rcx) 1)))
   (mov (r9) (cast (u 8) (mem (rsi) (rcx) 1)))
   (sub (r8) (r9))
   (jne diff.0)
   (add (rcx) 1)
   (jmp top.0)
   (lab :diff.0)
   (mov (rax) (r8))
   (ret)
   (lab :eq.0)
   (mov (rax) 0)
   (ret)))
 (proc :strlen.0.
  (params)
  (result)
  (clobber)
  (lenient)
  (stmts
   (mov (rax) 0)
   (lab :top.0)
   (mov (r8) (cast (u 8) (mem (rdi) (rax) 1)))
   (cmp (r8) 0)
   (je done.0)
   (add (rax) 1)
   (jmp top.0)
   (lab :done.0)
   (ret))))
"""

proc stripIndex(t: string): string =
  ## Text surgery invalidates the embedded index; all modules are passed on
  ## the nifasm command line, so the (lazy-load) index is not needed.
  result = t
  let ia = result.find("(.indexat")
  if ia >= 0:
    let e = result.find(')', ia)
    result = result[0 ..< ia] & result[e+1 .. ^1]
  let ix = result.rfind("(.index")
  if ix >= 0: result = result[0 ..< ix]

proc runCapture(exe: string; timeoutMs = 120_000): tuple[outp: string; code: int] =
  ## Run a produced binary with a deadline (a miscompile hangs as readily as
  ## it crashes); output drained after exit.
  var p = startProcess(exe, args = [], options = {poStdErrToStdOut})
  var waited = 0
  while waited < timeoutMs and p.running:
    sleep 20
    waited += 20
  if p.running:
    p.terminate()
    sleep 50
    if p.running: p.kill()
    discard p.waitForExit
    p.close
    return ("", 124)
  result.outp = p.outputStream.readAll
  result.code = p.waitForExit
  p.close

proc issueSummary(issues: seq[Issue]): string =
  var parts: seq[string] = @[]
  for (cat, n, ex) in issueHistogram(issues):
    parts.add cat & "×" & $n & " (" & ex & ")"
  result = parts.join("; ")

proc cmdSplice(src: string; funcSubs: seq[string]; doRun: bool; keep: bool) =
  let work = outDir() / "splice"
  # --keep reuses the two builds (they dominate the runtime), so per-function
  # attribution sweeps only re-translate, re-splice and re-link.
  let reuse = keep and dirExists(work / "nat") and dirExists(work / "gcc")
  if not reuse:
    removeDir work
    createDir work
    echo "building native (arkham + nifasm) …"
    discard buildNative(src, work)
    echo "building gcc -O3 …"
    discard buildGcc(src, work, GccSpliceFlags)
  var asmFiles: seq[string] = @[]
  for f in walkDirRec(work / "nat"):
    if f.endsWith(".asm.nif"): asmFiles.add f
  let d = asmFiles[0].parentDir
  let mainMod = d / (d.extractFilename & ".asm.nif")
  var others = asmFiles.filterIt(it != mainMod)
  others.sort
  let ordered = @[mainMod] & others
  var gccExe = ""
  for f in walkDirRec(work / "gcc"):
    if '.' notin f.extractFilename and fpUserExec in getFilePermissions(f):
      gccExe = f
  if gccExe.len == 0: quit "no gcc executable under " & work / "gcc"
  let (_, gccFuncs) = disasmGcc(gccExe)
  let info = readElfInfo(gccExe)
  var mods: seq[NativeModule] = @[]
  for f in ordered: mods.add parseNativeModule(f)
  var env = buildSpliceEnv(mods)
  env.dwarf = readDwarfSigs(gccExe)

  const SysVArg = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
  type Splice = object
    modIdx: int
    bodyStart, bodyEnd: int
    newBody, name: string
  var splices: seq[Splice] = @[]
  for fn in gccFuncs:
    var hit = false
    for sub in funcSubs:
      if sub.len > 0 and sub in fn.name: hit = true
    if not hit or fn.lines.len == 0 or isRuntimeGlue(fn.name): continue
    if fn.name notin env.procs:
      echo "SKIP   ", fn.name, ": no native proc has this mangled name"
      continue
    let sig = env.procs[fn.name]
    # The flattened per-eightbyte register sequence must be exactly the SysV
    # prefix — then gcc's view of the arguments (which splits ≤16B by-value
    # aggregates over the same register pairs) lines up with the header.
    var flat: seq[string] = @[]
    for p in sig.params: flat.add p.regs
    var targetOk = sig.scalarOk and flat.len <= 6 and
                   (not sig.hasResult or
                    sig.resultRegs in [@["rax"], @["rax", "rdx"]])
    if targetOk:
      for idx, r in flat:
        if r != SysVArg[idx]: targetOk = false
    if not targetOk:
      echo "SKIP   ", fn.name, ": target signature is not plain-SysV scalar"
      continue
    if env.dwarf.len > 0 and fn.name in env.dwarf:
      let (np, hr) = env.dwarf[fn.name]
      if np != sig.params.len or hr != sig.hasResult:
        echo "SKIP   ", fn.name, ": OVERLOAD MISMATCH — gcc side has ", np,
             " params/ret=", hr, ", native header has ", sig.params.len,
             "/ret=", sig.hasResult, " (ordinal divergence)"
        continue
    env.targetModule = env.procModule[fn.name]
    let (_, body, issues) = translateFunc(fn, info, addr env)
    if issues.len > 0:
      echo "SKIP   ", fn.name, ": ", issueSummary(issues)
      continue
    var modIdx = -1
    for mi, m in mods:
      if m.module == env.targetModule: modIdx = mi
    var found = false
    for p in mods[modIdx].procs:
      if gccKey(p.fullName) == fn.name:
        splices.add Splice(modIdx: modIdx, bodyStart: p.bodyStart,
                           bodyEnd: p.bodyEnd,
                           newBody: spliceGlueBody(body, sig), name: fn.name)
        found = true
    if found:
      echo "SPLICE ", fn.name, " (", fn.lines.len, " gcc insns) → module ",
           env.targetModule
  if splices.len == 0:
    quit "nothing spliced"

  # Text surgery: per module, replace body spans back-to-front.
  let modDir = work / "mod"
  createDir modDir
  var newTexts: seq[string] = @[]
  for m in mods: newTexts.add m.text
  splices.sort proc(a, b: Splice): int = b.bodyStart - a.bodyStart
  var touched = initHashSet[int]()
  for sp in splices:
    newTexts[sp.modIdx] = newTexts[sp.modIdx][0 ..< sp.bodyStart] &
                          sp.newBody & newTexts[sp.modIdx][sp.bodyEnd .. ^1]
    touched.incl sp.modIdx
  var splicedFiles: seq[string] = @[]
  for mi, m in mods:
    let dst = modDir / m.file.extractFilename
    if mi in touched:
      # The surgery invalidated the embedded index, and nifasm's cross-module
      # resolution requires one — recompute it with nimony's reindex tool.
      writeFile(dst, stripIndex(newTexts[mi]))
      discard run(@[binDir() / "reindex", dst])
    else:
      copyFile(m.file, dst)
    splicedFiles.add dst
  if env.usedGccrt:
    # The injected libc-replacement module: gcc-synthesized memcpy/memset/
    # memcmp/strlen calls in spliced bodies resolve to these lenient procs.
    let rt = modDir / "gccrt.asm.nif"
    writeFile(rt, GccRtModule)
    discard run(@[binDir() / "reindex", rt])
    splicedFiles.add rt
  # (Re-)link both with --symmap so callgrind output can be bucketed into
  # per-function spans (the ELF itself carries no symbol table).
  let baseElf = work / "native.elf"
  let splicedElf = work / "spliced.elf"
  writeFile(work / "base.symmap",
    run(@[repoDir() / "bin" / "nifasm", "--symmap", "-o:" & baseElf] & ordered))
  writeFile(work / "spliced.symmap",
    run(@[repoDir() / "bin" / "nifasm", "--symmap", "-o:" & splicedElf] & splicedFiles))
  echo "\nbaseline: ", baseElf, "  (", getFileSize(baseElf), " bytes)"
  echo "spliced:  ", splicedElf, " (", getFileSize(splicedElf), " bytes)"
  if doRun:
    let rb = runCapture(baseElf)
    let rs = runCapture(splicedElf)
    echo "\nbaseline run: exit ", rb.code, "\n", rb.outp
    echo "spliced run:  exit ", rs.code, "\n", rs.outp
    if rb.code == rs.code and rb.outp == rs.outp:
      echo "OUTPUTS IDENTICAL"
    else:
      echo "OUTPUTS DIFFER — splice is unsound for this function set"

proc main() =
  let args = commandLineParams()
  if args.len < 2:
    quit """usage: distillator compare   <workload.nim> [func-substr ...]
       distillator translate <workload.nim> <func-substr ...>
       distillator audit     <workload.nim>
       distillator splice    <workload.nim> <func-substr ...> [--run]"""
  let cmd = args[0]
  var src = args[1]
  if not src.isAbsolute: src = getCurrentDir() / src
  let rest = args[2..^1]
  case cmd
  of "compare":
    cmdCompare(src, if rest.len > 0: rest
                    else: @["rawDealloc", "deallocBigChunk", "rawAlloc", "getBigChunk"])
  of "translate":
    if rest.len == 0: quit "translate: name at least one function substring"
    cmdTranslate(src, rest, audit = false)
  of "audit":
    cmdTranslate(src, @[], audit = true)
  of "splice":
    let subs = rest.filterIt(it notin ["--run", "--keep"])
    if subs.len == 0: quit "splice: name at least one function substring"
    cmdSplice(src, subs, doRun = "--run" in rest, keep = "--keep" in rest)
  else:
    quit "unknown subcommand: " & cmd

main()
