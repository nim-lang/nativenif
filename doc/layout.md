# The board layout file

`arkham --layout:board.nif` describes the part an image is built for: where its
memory is, which region each section lives in, and where the
stacks and the heap go.


## Shape

```
(layout
 (flash (startAddress 134217728) (megabytes 1))
 (sram  (startAddress 536870912) (kilobytes 128))
 (stacks (slots 4) (kilobytes 8) (tvar (bytes 512)))
 (heap   (kilobytes 32))
 (noinit (bytes 256))
 (core 0))
```

Sizes are tagged quantities, `(bytes N)`, `(kilobytes N)`, `(megabytes N)` exist.


## The two regions

`flash` is **the region the image ships in**: code, constants, and the initializer
image for globals. `sram` is **the region that holds nothing at reset**: globals,
stacks, heap, all established by the startup code — except for whatever
`(noinit …)` keeps back from it, which is the point of that row.

They are named for the parts rather than for permissions, and the imprecision is
deliberate. Whether the silicon is writable is beside the point — MPS2's region at
0x00000000 is ZBT SRAM and perfectly writable, real flash is writable through a
flash controller, and code can be run *from* RAM (an STM32 routine that erases
flash has to be). None of that changes where the image ships, which is the only
thing this file is deciding.

The initialized globals and the zeroed ones are one thing here. Whether a global
ships with a value is not something a layout has an opinion about; the split
inside `sram` is the image writer's high-water mark (see `doc/cortex_m.md` M6a).

Only one `flash` and one `sram` is what the format supports for now.

## Inside `sram`

Placed by nifasm inside `sram`, in this order:

0. **`noinit`** off the far END, before anything else is placed.
1. **globals** from the region base up — which is what every `movw`/`movt` site is
   already patched against.
2. **the heap**, 8-aligned above them.
3. **the stacks**, rounded up to the slot size.

The stacks go last because their alignment is the expensive one: rounding up
wastes whatever lies between them and the heap, and nothing after them pays for
it. An overflow of the region is a link-time error naming all four numbers.

`noinit` is placed from the other end for a reason given below: its address has to
be the same in two different runs, and the top is the only end of the region that
does not move when the globals or the heap change size.

## `noinit` — the region nothing establishes

Everything else in `sram` is established at reset: `.data` is copied in from
flash, `.bss` is zeroed. `(noinit <size>)` is the exception — bytes the startup
code is told to leave alone.

That exists for the one kind of state that must *not* be established, because it
is **written by the run that failed and read by the run after it**:

- a reboot counter, so a device that watchdog-resets every four seconds is
  detected rather than mistaken for one that works;
- the reset cause, so power-on and watchdog can be told apart at all;
- a crash record — the fault address, the last checkpoint reached.

Reached with `NoinitStart`/`NoinitSize`, the same shape as the heap's pair: MOVW/
MOVT sites the image writer patches, and naming one when the file keeps nothing
back is an error rather than a zero.

**It survives a WARM reset, not a power cycle.** The RAM is not re-initialized by
the image; it is not battery-backed either. A part with genuine backup SRAM keeps
its contents across power loss, which is a stronger guarantee and a different
feature — this one costs nothing but the address, and it works on every part.


## Stacks and thread-locals

`(slots N)` slots of one size, and **the slot size must be a power of two.**

A thread reaches its own thread-locals by *masking SP*.
`sp and not (slotSize-1)` is the base of the running thread's slot, in one
instruction, with no thread-ID register — ARMv7E-M has none.

The reservation sits at the **top** of each slot, just below where SP starts, so
the stack grows *down and away* from it rather than into it. The accessor is the
mask plus a constant add.

This implies:

* every stack is the same size, because the size is baked into an instruction;
* the boot stack obeys the same rule — `(core N)` selects which slot *this* image
  starts on, and its SP is that slot's top minus the reservation.

`(core N)` is a constant because there is **one image per core**: M-profile has no
architectural core id (no `MPIDR`), so a symmetric image would need a
vendor-specific CPUID register that arkham cannot know.

Thread-locals are not reachable from an interrupt handler. Handlers run on MSP
while threads may run on PSP, so masking SP inside one yields the handler's slot,
not the interrupted thread's — and in the simple case where everything runs on MSP
it would *appear* to work and break the day PSP is adopted.

## The heap

`(heap <size>)` is what the allocator gets pages from.

`lib/std/system/osalloc` reaches it through two intrinsics, `HeapStart` and
`HeapSize`, which arkham lowers to the same MOVW/MOVT pair the image writer
patches for `(dataload)`. They are link-time constants: a firmware image has no OS
to ask for pages, so the numbers cannot be computed at run time and are not the
runtime's to invent. Naming one without a `--layout:` is an error.

