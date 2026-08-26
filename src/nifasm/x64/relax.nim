#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## x86-64 branch relaxation and code alignment — the two layout passes that only
## a variable-length instruction set can have.
##
## Every jump is emitted long (`rel32`) and shrunk to `rel8` here, which is a
## fixpoint: shrinking one jump moves every byte after it, which can bring a
## second jump into `rel8` range. `alignCodeX64` then pads backward-branch
## targets to a 16-byte boundary, which moves code the other way — so both hand
## back an old->new position map, and every offset the assembler still tracks
## (gvar patch sites, the entry stub, the unwind rows, the listing) is carried
## through it.
##
## `threadJumps` and `invertCondJumps` are NOT here: they dispatch on
## `RelocKind`, which already carries the architecture, and run on AArch64 too.

import std / [tables, sets, algorithm, sequtils]
import "../core" / [buffers, relocs]

proc canUseShortJump(distance: int): bool {.inline.} =
  ## Whether a displacement fits x86's signed 8-bit (rel8) jump form.
  distance >= -128 and distance <= 127

proc isShrinkableX64(kind: RelocKind): bool {.inline.} =
  ## x86 `jmp rel32` (5B) and the `0F 8x` conditional jumps (6B) have a 2-byte
  ## rel8 form; `call` has no rel8 form, and `lea`/IAT-call/all ARM64 forms are
  ## fixed size — so only these shrink.
  kind in {rkJmp, rkJe, rkJne, rkJg, rkJl, rkJge, rkJle, rkJa, rkJb, rkJae, rkJbe,
           rkJo, rkJno, rkJs, rkJns, rkJp, rkJnp}

proc longSizeOf(kind: RelocKind): int {.inline.} =
  case kind
  of rkCall, rkJmp: 5
  of rkLea: 7
  of rkIatCall: 6
  of rkJe, rkJne, rkJg, rkJl, rkJge, rkJle, rkJa, rkJb, rkJae, rkJbe,
     rkJo, rkJno, rkJs, rkJns, rkJp, rkJnp: 6
  of rkB, rkBL, rkBEQ, rkBNE, rkCBZ, rkCBNZ, rkTBZ, rkTBNZ, rkADR, rkADRP: 4
  of rkADRADD: 8
  of rkTB, rkTBL, rkTBcond, rkTADR: 4
  of rkTMovwMovt, rkTMovwMovtFunc: 8
  of rkAvrRjmp, rkAvrRcall, rkAvrBrcond: 2
  of rkAvrJmp, rkAvrCall, rkAvrLdiAddr: 4

proc shortJccOpcode(kind: RelocKind): byte =
  case kind
  of rkJe: 0x74
  of rkJne: 0x75
  of rkJg: 0x7F
  of rkJl: 0x7C
  of rkJge: 0x7D
  of rkJle: 0x7E
  of rkJa: 0x77
  of rkJb: 0x72
  of rkJae: 0x73
  of rkJbe: 0x76
  of rkJo: 0x70
  of rkJno: 0x71
  of rkJs: 0x78
  of rkJns: 0x79
  of rkJp: 0x7A
  of rkJnp: 0x7B
  else: 0x74  # unreachable (guarded by isShrinkableX64)

proc emitX64Nops(data: var Bytes; n: int) =
  ## `n` bytes of x86 no-ops in as FEW instructions as possible (Intel's canonical
  ## multi-byte NOP forms, up to 9 bytes each). A pad before a loop head is executed
  ## on the fall-in path, so 11 × `0x90` would cost 11 decode slots where two long
  ## NOPs cost two.
  const Forms: array[1..9, seq[byte]] = [
    @[0x90'u8],
    @[0x66'u8, 0x90],
    @[0x0F'u8, 0x1F, 0x00],
    @[0x0F'u8, 0x1F, 0x40, 0x00],
    @[0x0F'u8, 0x1F, 0x44, 0x00, 0x00],
    @[0x66'u8, 0x0F, 0x1F, 0x44, 0x00, 0x00],
    @[0x0F'u8, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00],
    @[0x0F'u8, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    @[0x66'u8, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]]
  var r = n
  while r > 0:
    let k = min(r, 9)
    for b in Forms[k]: data.add b
    r -= k

proc alignPointPositions(buf: Buffer; alignLabels: seq[int]): seq[int] =
  ## Resolve alignment-candidate label IDS to byte positions in `buf`'s CURRENT
  ## layout: undefined labels are dropped, positions inside a layout-frozen
  ## `casejmp` region are dropped (nothing may be inserted there), duplicates
  ## collapse. Sorted ascending. Used both by `shortenX64Jumps` (to know which
  ## jumps a future pad would invalidate) and by `alignCodeX64` (to insert the
  ## pads) — one resolution rule, so the two views cannot drift.
  let lp = buf.labelPositions
  result = @[]
  for id in alignLabels:
    if id >= 0 and id < lp.len and lp[id] >= 0 and not inFixedRange(buf, lp[id]):
      result.add lp[id]
  result.sort()
  result = deduplicate(result, isSorted = true)

proc backwardBranchTargets*(buf: Buffer): seq[int] =
  ## Label ids targeted by a BACKWARD x86 `jmp`/`jcc` — loop heads, the alignment
  ## candidates `alignCodeX64` pads to a 16-byte boundary. Collect from the reloc
  ## list right before `shortenX64Jumps` (afterwards the shortened jumps are
  ## patched inline and no longer tracked).
  let lp = buf.labelPositions
  var seen = initHashSet[int]()
  for r in buf.relocs:
    if isShrinkableX64(r.kind) and int(r.target) < lp.len:
      let tp = lp[int(r.target)]
      if tp >= 0 and tp < r.position and int(r.target) notin seen:
        seen.incl int(r.target)
        result.add int(r.target)

proc crossesAlignPoint(points: seq[int]; a, b: int): bool {.inline.} =
  ## Would a pad inserted at one of the (sorted) `points` change the displacement
  ## between instruction position `a` and label position `b`? A pad at `p` shifts
  ## every byte — and every label — at position ≥ `p`, so the displacement changes
  ## iff a point lies in `(min(a,b), max(a,b)]`: a jump and a target that shift
  ## TOGETHER (both ≥ p, including a backward jump to the padded label itself)
  ## keep their distance; only a jump on the far side of the pad from its target
  ## sees the layout move.
  let lo = min(a, b)
  let hi = max(a, b)
  let i = upperBound(points, lo)          # first point > lo
  i < points.len and points[i] <= hi

proc alignCodeX64*(buf: var Buffer; alignLabels: seq[int]; alignment = 16): seq[int] =
  ## Pad the positions of `alignLabels` (proc entries, loop heads) to `alignment`
  ## with multi-byte NOPs, rewriting `buf` in place. Returns the old→new byte-
  ## position map (length `data.len + 1`) for the caller's external offsets, the
  ## same contract as `threadJumps`/`shortenX64Jumps`.
  ##
  ## MUST run AFTER `shortenX64Jumps`, and only with the SAME `alignLabels` that
  ## pass was given: the shortener keeps every jump whose displacement window
  ## crosses one of these points in rel32 form (a tracked reloc `finalize` patches
  ## from the remapped labels), so the rel8 jumps it patched inline are exactly
  ## the ones whose distances a pad here cannot change. The code base offset in
  ## the executable must itself be `alignment`-aligned for offset alignment to be
  ## address alignment (the static ELF's text starts at 0x400000+176, 176 = 16·11).
  let points = alignPointPositions(buf, alignLabels)
  let oldLen = buf.data.len
  # Pad size per point, in ascending order (earlier pads shift later points).
  var pads = newSeq[int](points.len)
  var shift = 0
  for i in 0 ..< points.len:
    pads[i] = (alignment - (points[i] + shift) mod alignment) mod alignment
    shift += pads[i]
  # Rebuild the bytes with the pads in, building the old→new map alongside.
  result = newSeq[int](oldLen + 1)
  var newData = initBytes()
  var pi = 0
  for oldI in 0 ..< oldLen:
    if pi < points.len and points[pi] == oldI:
      emitX64Nops(newData, pads[pi])
      inc pi
    result[oldI] = newData.len
    newData.add buf.data[oldI]
  if pi < points.len and points[pi] == oldLen:   # a point at the very end (degenerate)
    emitX64Nops(newData, pads[pi])
  result[oldLen] = newData.len
  # Remap everything the buffer itself tracks; a label AT a point moves to the
  # aligned boundary (its pad sits before it).
  for k in 0 ..< buf.labels.len:
    buf.labels[k].position = result[buf.labels[k].position]
  for k in 0 ..< buf.relocs.len:
    buf.relocs[k].position = result[buf.relocs[k].position]
  for k in 0 ..< buf.fixedRanges.len:
    buf.fixedRanges[k] = (result[buf.fixedRanges[k][0]], result[buf.fixedRanges[k][1]])
  buf.data = newData

proc shortenX64Jumps*(buf: var Buffer; alignLabels: seq[int] = @[]): seq[int] =
  ## Shrink x86 `jmp`/`jcc rel32` to `rel8` wherever the displacement fits a signed
  ## byte, rewriting `buf` in place. Returns an old→new byte-position map (length
  ## `buf.data.len + 1`, indexed by *original* offset) so the caller can remap any
  ## external code offsets it tracks — gvar/`lea` patch sites and the synthesized
  ## TLS-prologue entry — to the shortened layout.
  ##
  ## This is branch relaxation run *optimistically*: every shrinkable jump starts
  ## SHORT (the most compact possible layout), and we GROW back to long only the
  ## jumps whose displacement genuinely overflows rel8. Growing pushes later code
  ## apart, which can force further jumps to grow — so we iterate to a fixpoint.
  ## Growing is monotonic (a jump only ever goes short→long, never back), so it
  ## converges, and the result is *optimal*: the minimal set of long jumps, hence
  ## the maximal set of short ones. (The opposite, start-long-and-shrink, is also
  ## sound but suboptimal — it misses mutually-enabling pairs that each only fit
  ## once the other is short.) Each pass recomputes the layout in O(n log n) via a
  ## prefix-sum of the bytes saved so far + a binary search, so a big module costs
  ## O(passes · n log n) with passes typically 1–3.
  ##
  ## The final displacements are computed from the converged position map, so the
  ## emitted bytes are exact. Short jumps are patched inline and dropped from the
  ## reloc list; long forms are re-tracked at their new positions for
  ## `updateRelocDisplacements` to patch from the final labels.
  ##
  ## x86-only: `call`/`lea`/IAT-call and every ARM64 form keep their size. Intended
  ## for the static-ELF x64 path (no IAT call-site bookkeeping to invalidate).
  let oldLen = buf.data.len

  # Relocs in ascending position order — the layout/rebuild walks depend on it.
  var relocs = buf.relocs
  relocs.sort(proc (a, b: RelocEntry): int = cmp(a.position, b.position))

  # Old label position by id, for distance evaluation and final displacements.
  var labelPos = initTable[int, int]()
  for ld in buf.labels: labelPos[int(ld.id)] = ld.position

  # Every shrinkable jump starts short; non-shrinkable relocs are permanently long.
  # A jump inside a layout-frozen `casejmp` region must keep its emitted (long)
  # size — the computed `base + idx*N` target arithmetic depends on it.
  # A jump whose displacement window crosses an `alignLabels` point also stays
  # long: `alignCodeX64` will insert a NOP pad there AFTER this pass, and a rel8
  # patched inline here could not be re-patched (it is dropped from the reloc
  # list) — while a rel32 stays tracked and `finalize` recomputes it from the
  # padded labels. Jumps that shift TOGETHER with their target (the common
  # intra-proc/intra-loop case, including the loop back-jump to the padded head
  # itself) do not cross and stay shrinkable — see `crossesAlignPoint`.
  let alignPts = alignPointPositions(buf, alignLabels)
  var isShort = newSeq[bool](relocs.len)
  for i in 0 ..< relocs.len:
    isShort[i] = isShrinkableX64(relocs[i].kind) and
                 not inFixedRange(buf, relocs[i].position) and
                 not crossesAlignPoint(alignPts, relocs[i].position,
                                       labelPos.getOrDefault(int(relocs[i].target), relocs[i].position))

  # Old reloc positions in ascending order (== relocs order, already sorted), for
  # the per-pass binary search.
  var relocPositions = newSeq[int](relocs.len)
  for i in 0 ..< relocs.len: relocPositions[i] = relocs[i].position

  # ── fixpoint: grow every short jump that overflows rel8, until none do ──
  var changed = true
  while changed:
    changed = false
    # Prefix savings: savPrefix[k] = bytes removed by relocs[0 ..< k] (those before
    # index k). newPos(p) = p − savings of all relocs at an old position < p, found
    # by binary-searching `relocPositions` for the count below p.
    var savPrefix = newSeq[int](relocs.len + 1)
    for i in 0 ..< relocs.len:
      savPrefix[i + 1] = savPrefix[i] +
        (if isShort[i]: longSizeOf(relocs[i].kind) - 2 else: 0)
    proc newPos(p: int): int =
      let below = lowerBound(relocPositions, p)   # # of relocs with position < p
      p - savPrefix[below]
    for i in 0 ..< relocs.len:
      if not isShort[i]: continue
      let dist = newPos(labelPos[int(relocs[i].target)]) -
                 (newPos(relocs[i].position) + 2)   # rel8 measured from 2-byte end
      if not canUseShortJump(dist):
        isShort[i] = false                          # overflow → grow back to long
        changed = true

  # ── pass A: the old→new position map for the converged decisions ──
  result = newSeq[int](oldLen + 1)
  var newLen = 0
  var oldI = 0
  var ri = 0
  while oldI < oldLen:
    result[oldI] = newLen
    if ri < relocs.len and relocs[ri].position == oldI:
      newLen += (if isShort[ri]: 2 else: longSizeOf(relocs[ri].kind))
      oldI += relocs[ri].originalSize
      inc ri
    else:
      newLen += 1
      oldI += 1
  result[oldLen] = newLen

  # ── pass B: rebuild the bytes; patch short jumps, re-track long relocs ──
  var newData = initBytes()
  var newRelocs: seq[RelocEntry] = @[]
  oldI = 0
  ri = 0
  while oldI < oldLen:
    if ri < relocs.len and relocs[ri].position == oldI:
      let r = relocs[ri]
      if isShrinkableX64(r.kind) and isShort[ri]:
        let newSelf = result[r.position]
        let newTgt = result[labelPos[int(r.target)]]
        let disp = newTgt - (newSelf + 2)
        newData.add(if r.kind == rkJmp: 0xEB'u8 else: shortJccOpcode(r.kind))
        newData.add(byte(disp and 0xFF))
      else:
        for j in 0 ..< r.originalSize: newData.add buf.data[oldI + j]
        newRelocs.add RelocEntry(position: result[r.position], target: r.target,
                                 kind: r.kind, originalSize: r.originalSize)
      oldI += r.originalSize
      inc ri
    else:
      newData.add buf.data[oldI]
      inc oldI

  for k in 0 ..< buf.labels.len:
    buf.labels[k].position = result[buf.labels[k].position]
  for k in 0 ..< buf.fixedRanges.len:      # nothing shrinks INSIDE a fixed range
    buf.fixedRanges[k] = (result[buf.fixedRanges[k][0]], result[buf.fixedRanges[k][1]])
  buf.data = newData
  buf.relocs = newRelocs
