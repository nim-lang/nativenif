# The board layout file

`arkham --layout:board.nif` describes the part an image is built for: where its
memory is, which region each section lives in, what its console is, and where the
stacks and the heap go.

It replaces a command-line namespace that could not have grown into this. Regions
are a **list**; a stack slot has a size *and* a count *and* a thread-local
reservation; a board may have three RAMs and put `.data` in one of them. None of
that survives being flattened into `--flag:value` pairs.

## One reader

arkham parses the file and **forwards it into the asm-NIF** as a `(layout …)`
declaration. nifasm — which needs the regions to place segments — reads that tree
rather than opening the file a second time.

Two parsers of one file is two chances to disagree about what a region means, and
the disagreement would not be a diagnostic: it would be an image that loads at the
wrong address. The forward is also **normalized to bytes**, so the unit arithmetic
happens exactly once.

The file is written in nifasm's own tag vocabulary (`doc/instructions.md`), which
is what makes that forwarding a splice rather than a translation.

## Shape

```
(.nif27)
(layout
 (region flash rom (startAddress 134217728) (megabytes 1))
 (region sram  ram (startAddress 536870912) (kilobytes 128))

 (place code  flash)
 (place const flash)
 (place gvar  sram)

 (writesTo serial (startAddress 1073758208))

 (stacks sram (slots 4) (kilobytes 8) (tvar (bytes 512)))
 (heap   sram (kilobytes 32))
 (core 0))
```

**Sizes are tagged quantities.** NIF has no `4K` literal, and a bare number in a
layout file is exactly the place where a reader guesses the unit and is wrong. So
`(bytes N)`, `(kilobytes N)`, `(megabytes N)` — and an untagged number is an
error, not a byte count.

`(startAddress …)` is an address. Addresses and sizes are both plain integers in
NIF, so they are told apart by their tag — and spelled out, because a row holds
two numbers and the reader should not have to remember which is which.

## Regions and placement

A region is `rom` (holds what the image ships with) or `ram` (holds nothing at
reset). `code` and `const` must be placed in a `rom` region and `gvar` in a `ram`
one — placing code in RAM would mean an image with nothing to copy it *from*.

**The section names are NIF's and Nimony's, not the linker's:** `code`, `const`,
`gvar`. One vocabulary across the toolchain is worth more than matching a
convention whose own names are accidents — `.bss` stands for *Block Started by
Symbol*, a 1950s IBM assembler directive, and has meant "the zeroed globals" only
by habit ever since.

`gvar` covers the initialized globals **and** the zeroed ones. Whether a global
ships with a value is not something a layout has an opinion about; the split
inside the region is the image writer's, and it is a high-water mark rather than
two placements (see `doc/cortex_m.md` M6a). Their initializer image ships in the
region `code` is placed in, and the startup copy is what puts it where `(place
gvar …)` says.

Today `gvar`, the stacks and the heap must all name the **same** region: the image
emits one SRAM segment. A part with a separate CCM/DTCM is exactly why the file
names regions individually, and lifting that restriction is a change to the image
writer rather than to this vocabulary.

## Inside the RAM region

Placed by nifasm, in this order:

1. **globals** from the region base up — which is what every `movw`/`movt` site is
   already patched against.
2. **the heap**, 8-aligned above them.
3. **the stacks**, rounded up to the slot size.

The stacks go last because their alignment is the expensive one: rounding up
wastes whatever lies between them and the heap, and nothing after them pays for
it. An overflow of the region is a link-time error naming all four numbers.

## Stacks and thread-locals

`(slots N)` slots of one size, and **the slot size must be a power of two.**

That is not tidiness: a thread reaches its own thread-locals by *masking SP*.
`sp and not (slotSize-1)` is the base of the running thread's slot, in one
instruction, with no thread-ID register — ARMv7E-M has none, so the alternative is
a global the scheduler updates on every switch.

The reservation sits at the **top** of each slot, just below where SP starts, so
the stack grows *down and away* from it rather than into it. The accessor is the
mask plus a constant add.

Two consequences worth stating rather than discovering:

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

`(heap <region> <size>)` is what the allocator gets pages from. There is no
`.bss` array standing in for it: an array would be a second answer to "how much
RAM may the allocator have?", and the file already answers that in the same place
it sizes the stacks and bounds the globals — so the three cannot silently add up
to more than the part has.

`lib/std/system/osalloc` reaches it through two intrinsics, `HeapStart` and
`HeapSize`, which arkham lowers to the same MOVW/MOVT pair the image writer
patches for `(dataload)`. They are link-time constants: a firmware image has no OS
to ask for pages, so the numbers cannot be computed at run time and are not the
runtime's to invent. Naming one without a `--layout:` is an error rather than a
default.

The page allocator is a bump: `osDeallocPages` can only give back the last thing
it handed out, and anything else stays lost until reset. That is the trade for a
page allocator with no bookkeeping of its own, and `alloc.nim` recycles within its
own chunks regardless.

A heap SHARED between threads additionally needs atomics — `alloc.nim`'s
lock-free paths are behind `hasThreadSupport` — and ARMv7-M `ldrex`/`strex` are
not implemented yet. Single-threaded is what works today; a threaded image is
refused by name at the first atomic rather than racing.

## Where `write` goes

A Leng program says `importc "write"` and `importc "exit"`. On a hosted target
those come from libc; on a bare board there is no libc and no OS, so arkham
synthesizes both — and `(writesTo …)` picks which bodies.

`(writesTo debugger)` emits `bkpt #0xAB` with the operation in r0: a debug agent
(QEMU, or a probe) intercepts the breakpoint, performs the I/O **on your machine**
and resumes. `exit` sets the process's status the same way. With nothing attached
the breakpoint faults and the program dies silently.

`(writesTo serial (startAddress …))` emits a real loop: poll the UART's status
register, store the byte to its data register. The bytes leave a pin. `exit` has
nowhere to report to, so it parks the core on `wfi`.

Both names say **what must be attached**, because that is the thing that is
actually got wrong — "I flashed it and nothing printed". Saying it here *and* on
the command line is refused: a contradiction, not a precedence question.

This is temporary. Implementing `write` is the standard library's job, not a code
generator's — a driver compiled into the backend can only ever be one driver — and
it moves there once `{.assembler.}` works on Cortex-M. See `doc/cortex_m.md` M6e.
