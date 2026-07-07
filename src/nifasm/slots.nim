import sem

type
  Slot* = object
    offset*, size*: int

  SlotManager* = object
    stackSize*: int
    maxStackSize*: int   ## high-water mark of `stackSize`. A `(scope …)` reclaims its
                         ## slots by resetting `stackSize` to the pre-scope value, but the
                         ## prologue must still reserve the peak: `(ssize)` is patched with
                         ## `max(stackSize, maxStackSize)`.
    freeSlots*: seq[Slot]

proc initSlotManager*(): SlotManager =
  result.stackSize = 0
  result.maxStackSize = 0
  result.freeSlots = @[]

proc alignedSize*(t: Type; slotAlign = 8): int =
  ## Slot footprint, rounded up to the slot's granularity. `slotAlign` is the
  ## STACK-slot alignment (≥ 8) — distinct from the type's natural alignment, which
  ## drives struct-field layout. A bigger slot alignment also pads the footprint so
  ## the NEXT slot stays aligned.
  let a = max(8, slotAlign)
  (asmSizeOf(t) + a - 1) and not (a - 1)

proc allocSlotUp*(m: var SlotManager; t: Type; slotAlign = 8): int =
  ## Positive, base-relative slot offset for architectures that address locals
  ## upward from a stack pointer lowered by `sub sp, sp, #stackSize` (AArch64; also
  ## x86-64 here). Offsets grow 0, 8, 16, … so they fit the unsigned-immediate
  ## LDR/STR forms. With `slotAlign > 8` the slot START is aligned first (SP is kept
  ## 16-aligned, so a 16-aligned offset yields a 16-aligned address).
  let a = max(8, slotAlign)
  m.stackSize = alignTo(m.stackSize, a)
  result = m.stackSize
  m.stackSize += alignedSize(t, a)

proc allocSlot*(m: var SlotManager; t: Type): int =
  let size = alignedSize(t)
  var foundSlot = -1
  for i in 0..<m.freeSlots.len:
    if m.freeSlots[i].size >= size:
      foundSlot = i
      break
  
  if foundSlot != -1:
    let slot = m.freeSlots[foundSlot]
    result = slot.offset
    m.freeSlots.del(foundSlot)
    # If the slot is larger, split it
    if slot.size > size:
      # Existing logic from assembler.nim:
      # slot.offset is e.g. -16. size 16. Range [-32, -16) or [-16, 0)?
      # In assembler.nim:
      # ctx.stackSize += size (e.g. 8). offset = -8. Range [-8, 0).
      # ctx.stackSize += size (e.g. 8 -> 16). offset = -16. Range [-16, -8).
      # So offset is the lower bound? No, stack grows down.
      # rbp - 8.
      # If slot is (offset: -16, size: 16). It covers [-16, 0).
      # We need size 8.
      # We return -16. Range [-16, -8).
      # Remaining is [-8, 0). Offset -8. Size 8.
      # Calculation: newOffset = slot.offset + size. (-16 + 8 = -8).
      # newSize = slot.size - size. (16 - 8 = 8).
      m.freeSlots.add(Slot(offset: slot.offset + size, size: slot.size - size))
  else:
    m.stackSize += size
    result = -m.stackSize

proc killSlot*(m: var SlotManager; offset: int; t: Type) =
  var s = Slot(offset: offset, size: alignedSize(t))
  var i = 0
  while i < m.freeSlots.len:
    if m.freeSlots[i].offset + m.freeSlots[i].size == s.offset:
      # m.freeSlots[i] comes before s
      s.offset = m.freeSlots[i].offset
      s.size += m.freeSlots[i].size
      m.freeSlots.del(i)
    elif s.offset + s.size == m.freeSlots[i].offset:
      # s comes before m.freeSlots[i]
      s.size += m.freeSlots[i].size
      m.freeSlots.del(i)
    else:
      inc i
  m.freeSlots.add(s)

