# `nifasm` tag vocabulary

The complete tag set of the asm-NIF dialect `nifasm` reads: types, declarations,
addressing-mode expressions, registers, flags, and every machine instruction of
every target. See [nifasm.md](nifasm.md) for what the language *means*; this is
the authoritative list of what exists.

The `Enums` column names the Nim enums a tag becomes a member of, and thereby
which target it belongs to: `X64Inst` (x86-64), `A64Inst` (AArch64), `MInst`
(Thumb-2 / Cortex-M), or several of them for the cross-target vocabulary. This
table is the input to
`tools/gen_instructions.nim`, which generates `src/nifasm/tags.nim` (the tag ids)
and `src/nifasm/model.nim` (the enums). Both are generated — edit this file, not
them, and regenerate from the repository root:

```sh
nim c tools/gen_instructions.nim && ./tools/gen_instructions doc/instructions.md
```

| Tag                    | Enums                       |   Description |
|------------------------|-----------------------------|---------------|
| `(bool)`               | NifasmType                  | boolean type |
| `(nil)`                | NifasmType                  | nil: the null-pointer value/type, compatible with any pointer |
| `(i N)`                | NifasmType                  | signed integer type of N bits |
| `(u N)`                | NifasmType                  | unsigned integer type of N bits |
| `(f N)`                | NifasmType                  | float type of N bits |
| `(ptr T)`              | NifasmType                  | pointer to single element |
| `(aptr T)`             | NifasmType                  | pointer to array of elements |
| `(array T N)`          | NifasmType                  | array type |
| `(type D ...)`         | NifasmDecl                  | type declaration |
| `(object ...)`         | NifasmType                  | object type definition |
| `(union ...)`          | NifasmType                  | union type definition |
| `(fld D T)`            | NifasmType                  | field definition |
| `(proc D ...)`         | NifasmDecl                  | proc declaration |
| `(params ...)`         | NifasmDecl                  | parameters block |
| `(param D L T)`        | NifasmDecl                  | parameter declaration |
| `(result D L T)`       | NifasmDecl                  | result value declaration |
| `(clobber ...)`        | NifasmDecl                  | clobbered registers list |
| `(var D L T)`          | NifasmDecl                  | variable declaration |
| `(arch x64/arm64)`     | NifasmDecl                  | architecture pragma: `x64`, `linux_arm64`, `arm64`, `win_x64`, `win_arm64`, `cortex_m` |
| `(s)`                  | X64Flag                 | stack slot location tag |
| `(align N)`            | NifasmExpr                  | stack-slot alignment annotation (child of `(s)`) |
| `(ssize)` / `(ssize N)` | NifasmExpr                 | stack size expression; the optional `N` adds N bytes at THIS site only (the prologue folds its 16-alignment pad in) |
| `(csize)`              | NifasmExpr                  | call stack size expression |
| `(dataload)`           | NifasmExpr                  | Cortex-M: flash address the `.data` initializer image is loaded from |
| `(datavma)`            | NifasmExpr                  | Cortex-M: SRAM address `.data` occupies at run time |
| `(datasize)`           | NifasmExpr                  | Cortex-M: bytes to copy from `(dataload)` to `(datavma)` |
| `(bsssize)`            | NifasmExpr                  | Cortex-M: bytes to zero immediately above `(datavma)` + `(datasize)` |
| `(arg S)`              | NifasmExpr                  | argument reference in prepare block |
| `(res S)`              | NifasmExpr                  | result reference in prepare block |
| `(prepare S ...)`      | X64Inst, A64Inst, MInst | prepare block for function call |
| `(mov D S)`            | X64Inst, A64Inst, MInst | move instruction |
| `(lea D S)`            | X64Inst, A64Inst, MInst | load effective address |
| `(movzx D S N)`        | X64Inst                  | D = the low `N` bits of S, ZERO-extended into the full 64-bit D (`N` is 8, 16 or 32) |
| `(movsx D S N)`        | X64Inst                  | D = the low `N` bits of S, SIGN-extended into the full 64-bit D (`N` is 8, 16 or 32) |
| `(movapd D S)`         | X64Inst                  | move aligned packed double |
| `(movsd D S)`          | X64Inst                  | move scalar double |
| `(movdqu D S)`         | X64Inst                  | move unaligned 128 bits (xmm/mem both sides; the access is inherently 16 bytes — the mem operand's scalar type is not consulted, matching the hardware) |
| `(add D S)`            | X64Inst, A64Inst, MInst | add instruction |
| `(sub D S)`            | X64Inst, A64Inst, MInst | subtract instruction |
| `(mul S)`              | X64Inst, A64Inst, MInst | unsigned multiply |
| `(imul D S)`           | X64Inst                  | signed multiply |
| `(div D S R)`          | X64Inst                  | unsigned divide |
| `(idiv D S R)`         | X64Inst                  | signed divide |
| `(sdiv D S)`           | A64Inst, MInst | signed divide |
| `(udiv D S)`           | A64Inst, MInst | unsigned divide |
| `(smulh D S)`          | A64Inst                  | signed multiply high (top 64 bits of D*S) |
| `(umulh D S)`          | A64Inst                  | unsigned multiply high (top 64 bits of D*S) |
| `(add3 D A B)`         | A64Inst, MInst | 3-operand add (D = A + B) |
| `(sub3 D A B)`         | A64Inst, MInst | 3-operand subtract (D = A - B) |
| `(mul3 D A B)`         | A64Inst, MInst | 3-operand multiply (D = A * B) |
| `(and3 D A B)`         | A64Inst, MInst | 3-operand bitwise and (D = A and B) |
| `(orr3 D A B)`         | A64Inst, MInst | 3-operand bitwise or (D = A or B) |
| `(eor3 D A B)`         | A64Inst, MInst | 3-operand bitwise xor (D = A xor B) |
| `(lsl3 D A B)`         | A64Inst, MInst | 3-operand logical shift left (D = A shl B) |
| `(lsr3 D A B)`         | A64Inst, MInst | 3-operand logical shift right (D = A shr B) |
| `(asr3 D A B)`         | A64Inst, MInst | 3-operand arithmetic shift right (D = A sar B) |
| `(addw D S)`           | A64Inst, MInst | 32-bit add (W-form, result zero-extended) |
| `(subw D S)`           | A64Inst, MInst | 32-bit subtract (W-form, result zero-extended) |
| `(mulw D S)`           | A64Inst, MInst | 32-bit multiply (W-form, result zero-extended) |
| `(addw3 D A B)`        | A64Inst, MInst | 32-bit 3-operand add (D = A + B, W-form) |
| `(subw3 D A B)`        | A64Inst, MInst | 32-bit 3-operand subtract (D = A - B, W-form) |
| `(mulw3 D A B)`        | A64Inst, MInst | 32-bit 3-operand multiply (D = A * B, W-form) |
| `(gload D S)`          | A64Inst, MInst | load scalar from global S: adrp + folded ldr (drops the address `add`) |
| `(gstore D S)`         | A64Inst, MInst | store scalar D to global S: adrp + folded str |
| `(addsd D S)`          | X64Inst                  | add scalar double |
| `(subsd D S)`          | X64Inst                  | subtract scalar double |
| `(mulsd D S)`          | X64Inst                  | multiply scalar double |
| `(divsd D S)`          | X64Inst                  | divide scalar double |
| `(movss D S)`          | X64Inst                  | move scalar single |
| `(addss D S)`          | X64Inst                  | add scalar single |
| `(subss D S)`          | X64Inst                  | subtract scalar single |
| `(mulss D S)`          | X64Inst                  | multiply scalar single |
| `(divss D S)`          | X64Inst                  | divide scalar single |
| `(cvtsi2sd D S)`       | X64Inst                  | int -> scalar double convert |
| `(cvtsi2ss D S)`       | X64Inst                  | int -> scalar single convert |
| `(cvttsd2si D S)`      | X64Inst                  | scalar double -> int convert (truncating) |
| `(cvttss2si D S)`      | X64Inst                  | scalar single -> int convert (truncating) |
| `(cvtsd2ss D S)`       | X64Inst                  | scalar double -> scalar single convert |
| `(cvtss2sd D S)`       | X64Inst                  | scalar single -> scalar double convert |
| `(comisd D S)`         | X64Inst                  | compare scalar double, set EFLAGS |
| `(comiss D S)`         | X64Inst                  | compare scalar single, set EFLAGS |
| `(movfq D S)`          | X64Inst                  | move 64 bits between gpr and xmm; `(movfq (xmmD) (xmmS))` is SSE `movq xmm,xmm` — D.lo = S.lo with D's high lane ZEROED (gcc's lane sanitizer before packed ops) |
| `(movfd D S)`          | X64Inst                  | move 32 bits between gpr and xmm |
| `(and D S)`            | X64Inst, A64Inst, MInst | bitwise and |
| `(or D S)`             | X64Inst                  | bitwise or |
| `(orr D S)`            | A64Inst, MInst | bitwise or |
| `(xor D S)`            | X64Inst                  | bitwise xor |
| `(eor D S)`            | A64Inst, MInst | bitwise xor |
| `(shl D S)`            | X64Inst                  | shift left |
| `(lsl D S)`            | A64Inst, MInst | logical shift left |
| `(shr D S)`            | X64Inst                  | shift right |
| `(lsr D S)`            | A64Inst, MInst | logical shift right |
| `(sal D S)`            | X64Inst                  | shift arithmetic left |
| `(sar D S)`            | X64Inst                  | shift arithmetic right |
| `(asr D S)`            | A64Inst, MInst | arithmetic shift right |
| `(inc O)`              | X64Inst                  | increment |
| `(dec O)`              | X64Inst                  | decrement |
| `(neg O)`              | X64Inst, A64Inst, MInst | negate |
| `(not O)`              | X64Inst                  | bitwise not |
| `(rol D S)`            | X64Inst                  | rotate left |
| `(ror D S)`            | X64Inst                  | rotate right |
| `(rcl D S)`            | X64Inst                  | rotate left through carry |
| `(rcr D S)`            | X64Inst                  | rotate right through carry |
| `(bsf D S)`            | X64Inst                  | bit scan forward |
| `(bsr D S)`            | X64Inst                  | bit scan reverse |
| `(bt D S)`             | X64Inst                  | bit test |
| `(bts D S)`            | X64Inst                  | bit test and set |
| `(btr D S)`            | X64Inst                  | bit test and reset |
| `(btc D S)`            | X64Inst                  | bit test and complement |
| `(cmp D S)`            | X64Inst, A64Inst, MInst | compare |
| `(test D S)`           | X64Inst                  | test |
| `(sete D)`             | X64Inst                  | set byte if equal |
| `(setz D)`             | X64Inst                  | set byte if zero |
| `(setne D)`            | X64Inst                  | set byte if not equal |
| `(setnz D)`            | X64Inst                  | set byte if not zero |
| `(seta D)`             | X64Inst                  | set byte if above |
| `(setnbe D)`           | X64Inst                  | set byte if not below or equal |
| `(setae D)`            | X64Inst                  | set byte if above or equal |
| `(setnb D)`            | X64Inst                  | set byte if not below |
| `(setnc D)`            | X64Inst                  | set byte if not carry |
| `(setb D)`             | X64Inst                  | set byte if below |
| `(setnae D)`           | X64Inst                  | set byte if not above or equal |
| `(setc D)`             | X64Inst                  | set byte if carry |
| `(setbe D)`            | X64Inst                  | set byte if below or equal |
| `(setna D)`            | X64Inst                  | set byte if not above |
| `(setg D)`             | X64Inst                  | set byte if greater |
| `(setnle D)`           | X64Inst                  | set byte if not less or equal |
| `(setge D)`            | X64Inst                  | set byte if greater or equal |
| `(setnl D)`            | X64Inst                  | set byte if not less |
| `(setl D)`             | X64Inst                  | set byte if less |
| `(setnge D)`           | X64Inst                  | set byte if not greater or equal |
| `(setle D)`            | X64Inst                  | set byte if less or equal |
| `(setng D)`            | X64Inst                  | set byte if not greater |
| `(seto D)`             | X64Inst                  | set byte if overflow |
| `(sets D)`             | X64Inst                  | set byte if sign |
| `(setp D)`             | X64Inst                  | set byte if parity |
| `(cmove D S)`          | X64Inst                  | conditional move if equal |
| `(cmovz D S)`          | X64Inst                  | conditional move if zero |
| `(cmovne D S)`         | X64Inst                  | conditional move if not equal |
| `(cmovnz D S)`         | X64Inst                  | conditional move if not zero |
| `(cmova D S)`          | X64Inst                  | conditional move if above |
| `(cmovnbe D S)`        | X64Inst                  | conditional move if not below or equal |
| `(cmovae D S)`         | X64Inst                  | conditional move if above or equal |
| `(cmovnb D S)`         | X64Inst                  | conditional move if not below |
| `(cmovnc D S)`         | X64Inst                  | conditional move if not carry |
| `(cmovb D S)`          | X64Inst                  | conditional move if below |
| `(cmovnae D S)`        | X64Inst                  | conditional move if not above or equal |
| `(cmovc D S)`          | X64Inst                  | conditional move if carry |
| `(cmovbe D S)`         | X64Inst                  | conditional move if below or equal |
| `(cmovna D S)`         | X64Inst                  | conditional move if not above |
| `(cmovg D S)`          | X64Inst                  | conditional move if greater |
| `(cmovnle D S)`        | X64Inst                  | conditional move if not less or equal |
| `(cmovge D S)`         | X64Inst                  | conditional move if greater or equal |
| `(cmovnl D S)`         | X64Inst                  | conditional move if not less |
| `(cmovl D S)`          | X64Inst                  | conditional move if less |
| `(cmovnge D S)`        | X64Inst                  | conditional move if not greater or equal |
| `(cmovle D S)`         | X64Inst                  | conditional move if less or equal |
| `(cmovng D S)`         | X64Inst                  | conditional move if not greater |
| `(cmovo D S)`          | X64Inst                  | conditional move if overflow |
| `(cmovno D S)`         | X64Inst                  | conditional move if not overflow |
| `(cmovs D S)`          | X64Inst                  | conditional move if sign |
| `(cmovns D S)`         | X64Inst                  | conditional move if not sign |
| `(cmovp D S)`          | X64Inst                  | conditional move if parity |
| `(cmovnp D S)`         | X64Inst                  | conditional move if not parity |
| `(cmovpe D S)`         | X64Inst                  | conditional move if parity even (alias for p) |
| `(cmovpo D S)`         | X64Inst                  | conditional move if parity odd (alias for np) |
| `(jmp L)`              | X64Inst                  | unconditional jump |
| `(je L)`               | X64Inst                  | jump if equal |
| `(jz L)`               | X64Inst                  | jump if zero |
| `(jne L)`              | X64Inst                  | jump if not equal |
| `(jnz L)`              | X64Inst                  | jump if not zero |
| `(jg L)`               | X64Inst                  | jump if greater |
| `(jng L)`              | X64Inst                  | jump if not greater |
| `(jge L)`              | X64Inst                  | jump if greater or equal |
| `(jnge L)`             | X64Inst                  | jump if not greater or equal |
| `(ja L)`               | X64Inst                  | jump if above |
| `(jna L)`              | X64Inst                  | jump if not above |
| `(jae L)`              | X64Inst                  | jump if above or equal |
| `(jnae L)`             | X64Inst                  | jump if not above or equal |
| `(jl L)`               | X64Inst                  | jump if less |
| `(jle L)`              | X64Inst                  | jump if less or equal |
| `(jb L)`               | X64Inst                  | jump if below |
| `(jbe L)`              | X64Inst                  | jump if below or equal |
| `(jo L)`               | X64Inst                  | jump if overflow |
| `(jno L)`              | X64Inst                  | jump if not overflow |
| `(jp L)`               | X64Inst                  | jump if parity (unordered float compare) |
| `(call T ...)`         | X64Inst, A64Inst, MInst | function call marker inside prepare |
| `(extcall)`            | X64Inst, A64Inst, MInst | external call marker inside prepare |
| `(tailcall T ...)`     | A64Inst                  | tail-call marker inside prepare: branch, no link |
| `(popframe)`           | A64Inst                  | undo this proc's prologue (frame sub + saved pairs) |
| `(iat S)`              | X64Inst                  | indirect call through IAT (Import Address Table) |
| `(ret)`                | X64Inst, A64Inst, MInst | return instruction |
| `(push O)`             | X64Inst                  | push to stack |
| `(pop O)`              | X64Inst                  | pop from stack |
| `(nop)`                | X64Inst, A64Inst, MInst | no operation |
| `(syscall)`            | X64Inst                  | system call |
| `(svc N)`              | A64Inst                  | supervisor call (system call) |
| `(adr D L)`            | A64Inst, MInst | load address of label |
| `(ldr D S)`            | A64Inst, MInst | load register |
| `(str D S)`            | A64Inst, MInst | store register |
| `(stp D1 D2 S)`        | A64Inst                  | store pair |
| `(ldp D1 D2 S)`        | A64Inst                  | load pair |
| `(b L)`                | A64Inst, MInst | branch (unconditional jump) |
| `(bl L)`               | A64Inst, MInst | branch with link (function call) |
| `(beq L)`              | A64Inst, MInst | branch if equal |
| `(bne L)`              | A64Inst, MInst | branch if not equal |
| `(blt L)`              | A64Inst, MInst | branch if less than (signed) |
| `(ble L)`              | A64Inst, MInst | branch if less or equal (signed) |
| `(bgt L)`              | A64Inst, MInst | branch if greater than (signed) |
| `(bge L)`              | A64Inst, MInst | branch if greater or equal (signed) |
| `(blo L)`              | A64Inst, MInst | branch if lower (unsigned <) |
| `(bls L)`              | A64Inst, MInst | branch if lower or same (unsigned <=) |
| `(bhi L)`              | A64Inst, MInst | branch if higher (unsigned >) |
| `(bhs L)`              | A64Inst, MInst | branch if higher or same (unsigned >=) |
| `(cbz S L)`            | A64Inst, MInst | branch to L if S is zero (no flags read) |
| `(cbnz S L)`           | A64Inst, MInst | branch to L if S is non-zero (no flags read) |
| `(cseleq D S1 S2)`     | A64Inst                  | conditional select: D = if equal then S1 else S2 |
| `(cselne D S1 S2)`     | A64Inst                  | conditional select: D = if not equal then S1 else S2 |
| `(csellt D S1 S2)`     | A64Inst, MInst | conditional select: D = if less than (signed) then S1 else S2 |
| `(cselle D S1 S2)`     | A64Inst                  | conditional select: D = if less or equal (signed) then S1 else S2 |
| `(cselgt D S1 S2)`     | A64Inst                  | conditional select: D = if greater than (signed) then S1 else S2 |
| `(cselge D S1 S2)`     | A64Inst                  | conditional select: D = if greater or equal (signed) then S1 else S2 |
| `(csello D S1 S2)`     | A64Inst                  | conditional select: D = if lower (unsigned <) then S1 else S2 |
| `(csells D S1 S2)`     | A64Inst                  | conditional select: D = if lower or same (unsigned <=) then S1 else S2 |
| `(cselhi D S1 S2)`     | A64Inst                  | conditional select: D = if higher (unsigned >) then S1 else S2 |
| `(cselhs D S1 S2)`     | A64Inst                  | conditional select: D = if higher or same (unsigned >=) then S1 else S2 |
| `(cseteq D)`           | A64Inst                  | conditional set: D = if equal then 1 else 0 |
| `(csetne D)`           | A64Inst                  | conditional set: D = if not equal then 1 else 0 |
| `(csetlt D)`           | A64Inst                  | conditional set: D = if less than (signed) then 1 else 0 |
| `(csetle D)`           | A64Inst                  | conditional set: D = if less or equal (signed) then 1 else 0 |
| `(csetgt D)`           | A64Inst                  | conditional set: D = if greater than (signed) then 1 else 0 |
| `(csetge D)`           | A64Inst                  | conditional set: D = if greater or equal (signed) then 1 else 0 |
| `(csetlo D)`           | A64Inst                  | conditional set: D = if lower (unsigned <) then 1 else 0 |
| `(csetls D)`           | A64Inst                  | conditional set: D = if lower or same (unsigned <=) then 1 else 0 |
| `(csethi D)`           | A64Inst                  | conditional set: D = if higher (unsigned >) then 1 else 0 |
| `(cseths D)`           | A64Inst                  | conditional set: D = if higher or same (unsigned >=) then 1 else 0 |
| `(lab L)`              | X64Inst, A64Inst, MInst | label definition |
| `(ite ...)`            | X64Inst, A64Inst, MInst | if-then-else structure |
| `(loop ...)`           | X64Inst, A64Inst, MInst | loop structure |
| `(stmts ...)`          | X64Inst, A64Inst, MInst | statement block |
| `(cfvar D)`            | NifasmDecl                  | control flow variable declaration |
| `(jtrue ...)`          | X64Inst, A64Inst, MInst | set control flow variable(s) to true |
| `(dot B F)`            | NifasmExpr                  | field access |
| `(at B I)`             | NifasmExpr                  | array index |
| `(mem ...)`            | NifasmExpr                  | memory reference: `(mem base)`, `(mem base disp)`, `(mem base index scale [disp])` (base/index are raw registers or register-homed locals/params), or the no-base scaled form `(mem 0 index scale [disp])` = `[index*scale + disp]` (x64: SIB base=101; the literal `0` base is unambiguous since a real base is never an immediate) |
| `(rodata L S)`         | NifasmDecl                  | read-only data (string/bytes) |
| `(gvar D L T)`         | NifasmDecl                  | global variable |
| `(tvar D L T)`         | NifasmDecl                  | thread local variable |
| `(imp S)`              | NifasmDecl                  | import dynamic library |
| `(extproc D S)`        | NifasmDecl                  | external proc from imported library |
| `(syproc D ...)`       | NifasmDecl                  | system-call proc declaration (proctype + clobbers + number) |
| `(kill S)`             | X64Inst, A64Inst, MInst | kill variable |
| `(cast T E)`         | NifasmExpr                  | type cast; over a memory operand it retypes (and thereby sizes) the access; over a REGISTER operand of an x64 ALU instruction (add/sub/and/or/xor/cmp/test/shl/shr/sar/neg/not) an explicit sub-width int type (8/16/32 bits) sizes the OPERATION: 32-bit zero-extends the destination, 8/16-bit preserve its upper bits, flags and shift-count masking follow the width. Never inferred from a symbol's declared type, and `mov` still rejects a cast register destination |
| `(reloc O S)`          | NifasmExpr                  | rodata relocation: bake symbol S's address at byte offset O |
| `(lock I)`             | X64Inst                  | atomic lock prefix |
| `(xchg D S)`           | X64Inst                  | atomic exchange |
| `(cmpxchg D S)`        | X64Inst                  | atomic compare and exchange |
| `(xadd D S)`           | X64Inst                  | atomic exchange and add |
| `(cmpxchg8b D)`        | X64Inst                  | atomic compare and exchange 8 bytes |
| `(mfence)`             | X64Inst                  | memory fence |
| `(sfence)`             | X64Inst                  | store fence |
| `(lfence)`             | X64Inst                  | load fence |
| `(pause)`              | X64Inst                  | pause |
| `(clflush O)`          | X64Inst                  | cache line flush |
| `(clflushopt O)`       | X64Inst                  | optimized cache line flush |
| `(prefetcht0 O)`       | X64Inst                  | prefetch t0 |
| `(prefetcht1 O)`       | X64Inst                  | prefetch t1 |
| `(prefetcht2 O)`       | X64Inst                  | prefetch t2 |
| `(prefetchnta O)`      | X64Inst                  | prefetch non-temporal |
| `(rax)`              | X64Reg                   | register rax |
| `(rbx)`              | X64Reg                   | register rbx |
| `(rcx)`              | X64Reg                   | register rcx |
| `(rdx)`              | X64Reg                   | register rdx |
| `(rsi)`              | X64Reg                   | register rsi |
| `(rdi)`              | X64Reg                   | register rdi |
| `(rbp)`              | X64Reg                   | register rbp |
| `(rsp)`              | X64Reg                   | register rsp |
| `(r8)`               | X64Reg, MReg             | register r8 |
| `(r9)`               | X64Reg, MReg             | register r9 |
| `(r10)`              | X64Reg, MReg             | register r10 |
| `(r11)`              | X64Reg, MReg             | register r11 |
| `(r12)`              | X64Reg, MReg             | register r12 |
| `(r13)`              | X64Reg                   | register r13 |
| `(r14)`              | X64Reg                   | register r14 |
| `(r15)`              | X64Reg                   | register r15 |
| `(r0)`               | X64Reg, MReg             | register r0 (alias) |
| `(r1)`               | X64Reg, MReg             | register r1 (alias) |
| `(r2)`               | X64Reg, MReg             | register r2 (alias) |
| `(r3)`               | X64Reg, MReg             | register r3 (alias) |
| `(r4)`               | X64Reg, MReg             | register r4 (alias) |
| `(r5)`               | X64Reg, MReg             | register r5 (alias) |
| `(r6)`               | X64Reg, MReg             | register r6 (alias) |
| `(r7)`               | X64Reg, MReg             | register r7 (alias) |
| `(xmm0)`             | X64Reg                   | register xmm0 |
| `(xmm1)`             | X64Reg                   | register xmm1 |
| `(xmm2)`             | X64Reg                   | register xmm2 |
| `(xmm3)`             | X64Reg                   | register xmm3 |
| `(xmm4)`             | X64Reg                   | register xmm4 |
| `(xmm5)`             | X64Reg                   | register xmm5 |
| `(xmm6)`             | X64Reg                   | register xmm6 |
| `(xmm7)`             | X64Reg                   | register xmm7 |
| `(xmm8)`             | X64Reg                   | register xmm8 |
| `(xmm9)`             | X64Reg                   | register xmm9 |
| `(xmm10)`            | X64Reg                   | register xmm10 |
| `(xmm11)`            | X64Reg                   | register xmm11 |
| `(xmm12)`            | X64Reg                   | register xmm12 |
| `(xmm13)`            | X64Reg                   | register xmm13 |
| `(xmm14)`            | X64Reg                   | register xmm14 |
| `(xmm15)`            | X64Reg                   | register xmm15 |
| `(x0)`               | A64Reg                   | register x0 |
| `(x1)`               | A64Reg                   | register x1 |
| `(x2)`               | A64Reg                   | register x2 |
| `(x3)`               | A64Reg                   | register x3 |
| `(x4)`               | A64Reg                   | register x4 |
| `(x5)`               | A64Reg                   | register x5 |
| `(x6)`               | A64Reg                   | register x6 |
| `(x7)`               | A64Reg                   | register x7 |
| `(x8)`               | A64Reg                   | register x8 |
| `(x9)`               | A64Reg                   | register x9 |
| `(x10)`              | A64Reg                   | register x10 |
| `(x11)`              | A64Reg                   | register x11 |
| `(x12)`              | A64Reg                   | register x12 |
| `(x13)`              | A64Reg                   | register x13 |
| `(x14)`              | A64Reg                   | register x14 |
| `(x15)`              | A64Reg                   | register x15 |
| `(x16)`              | A64Reg                   | register x16 |
| `(x17)`              | A64Reg                   | register x17 |
| `(x18)`              | A64Reg                   | register x18 |
| `(x19)`              | A64Reg                   | register x19 |
| `(x20)`              | A64Reg                   | register x20 |
| `(x21)`              | A64Reg                   | register x21 |
| `(x22)`              | A64Reg                   | register x22 |
| `(x23)`              | A64Reg                   | register x23 |
| `(x24)`              | A64Reg                   | register x24 |
| `(x25)`              | A64Reg                   | register x25 |
| `(x26)`              | A64Reg                   | register x26 |
| `(x27)`              | A64Reg                   | register x27 |
| `(x28)`              | A64Reg                   | register x28 |
| `(x29)`              | A64Reg                   | register x29 |
| `(x30)`              | A64Reg                   | register x30 |
| `(sp)`               | A64Reg, MReg             | stack pointer |
| `(w0)`               | A64Reg                   | register w0 (32-bit) |
| `(w1)`               | A64Reg                   | register w1 (32-bit) |
| `(w2)`               | A64Reg                   | register w2 (32-bit) |
| `(w3)`               | A64Reg                   | register w3 (32-bit) |
| `(w4)`               | A64Reg                   | register w4 (32-bit) |
| `(w5)`               | A64Reg                   | register w5 (32-bit) |
| `(w6)`               | A64Reg                   | register w6 (32-bit) |
| `(w7)`               | A64Reg                   | register w7 (32-bit) |
| `(w8)`               | A64Reg                   | register w8 (32-bit) |
| `(w9)`               | A64Reg                   | register w9 (32-bit) |
| `(w10)`              | A64Reg                   | register w10 (32-bit) |
| `(w11)`              | A64Reg                   | register w11 (32-bit) |
| `(w12)`              | A64Reg                   | register w12 (32-bit) |
| `(w13)`              | A64Reg                   | register w13 (32-bit) |
| `(w14)`              | A64Reg                   | register w14 (32-bit) |
| `(w15)`              | A64Reg                   | register w15 (32-bit) |
| `(w16)`              | A64Reg                   | register w16 (32-bit) |
| `(w17)`              | A64Reg                   | register w17 (32-bit) |
| `(w18)`              | A64Reg                   | register w18 (32-bit) |
| `(w19)`              | A64Reg                   | register w19 (32-bit) |
| `(w20)`              | A64Reg                   | register w20 (32-bit) |
| `(w21)`              | A64Reg                   | register w21 (32-bit) |
| `(w22)`              | A64Reg                   | register w22 (32-bit) |
| `(w23)`              | A64Reg                   | register w23 (32-bit) |
| `(w24)`              | A64Reg                   | register w24 (32-bit) |
| `(w25)`              | A64Reg                   | register w25 (32-bit) |
| `(w26)`              | A64Reg                   | register w26 (32-bit) |
| `(w27)`              | A64Reg                   | register w27 (32-bit) |
| `(w28)`              | A64Reg                   | register w28 (32-bit) |
| `(w29)`              | A64Reg                   | register w29 (32-bit) |
| `(w30)`              | A64Reg                   | register w30 (32-bit) |
| `(wsp)`              | A64Reg                   | stack pointer (32-bit) |
| `(lr)`               | A64Reg, MReg             | link register (alias for x30) |
| `(fp)`               | A64Reg                   | frame pointer (alias for x29) |
| `(xzr)`              | A64Reg                   | zero register |
| `(of)`               | X64Flag                 | overflow flag |
| `(no)`               | X64Flag                 | no overflow flag |
| `(zf)`               | X64Flag                 | zero flag |
| `(nz)`               | X64Flag                 | not zero flag |
| `(sf)`               | X64Flag                 | sign flag |
| `(ns)`               | X64Flag                 | not sign flag |
| `(cf)`               | X64Flag                 | carry flag |
| `(nc)`               | X64Flag                 | not carry flag |
| `(pf)`               | X64Flag                 | parity flag |
| `(np)`               | X64Flag                 | not parity flag |
| `(repmovsb)`         | X64Inst                 | repeat move byte string |
| `(repmovsw)`         | X64Inst                 | repeat move word string |
| `(repmovsd)`         | X64Inst                 | repeat move doubleword string |
| `(repmovsq)`         | X64Inst                 | repeat move quadword string |
| `(c N)`              | NifasmType              | character type of N bits |
| `(void)`             | NifasmType              | void type |
| `(varargs)`          | NifasmType              | C varargs marker type |
| `(flexarray T)`      | NifasmType              | flexible array member |
| `(enum T ...)`       | NifasmType              | enum type (base type + fields) |
| `(efld D N)`         | NifasmType              | enum field declaration |
| `(proctype ...)`     | NifasmType              | procedure (function pointer) type |
| `(ldaxr D S)`        | A64Inst                 | load-acquire exclusive register |
| `(stlxr St D S)`     | A64Inst                 | store-release exclusive register (St = status) |
| `(ldar D S)`         | A64Inst                 | load-acquire register |
| `(stlr D S)`         | A64Inst                 | store-release register |
| `(dmb)`              | A64Inst                 | data memory barrier (inner shareable) |
| `(clrex)`            | A64Inst                 | clear exclusive monitor |
| `(d0)`             | A64Reg                   | fp register d0 |
| `(d1)`             | A64Reg                   | fp register d1 |
| `(d2)`             | A64Reg                   | fp register d2 |
| `(d3)`             | A64Reg                   | fp register d3 |
| `(d4)`             | A64Reg                   | fp register d4 |
| `(d5)`             | A64Reg                   | fp register d5 |
| `(d6)`             | A64Reg                   | fp register d6 |
| `(d7)`             | A64Reg                   | fp register d7 |
| `(d8)`             | A64Reg                   | fp register d8 |
| `(d9)`             | A64Reg                   | fp register d9 |
| `(d10)`            | A64Reg                   | fp register d10 |
| `(d11)`            | A64Reg                   | fp register d11 |
| `(d12)`            | A64Reg                   | fp register d12 |
| `(d13)`            | A64Reg                   | fp register d13 |
| `(d14)`            | A64Reg                   | fp register d14 |
| `(d15)`            | A64Reg                   | fp register d15 |
| `(d16)`            | A64Reg                   | fp register d16 |
| `(d17)`            | A64Reg                   | fp register d17 |
| `(d18)`            | A64Reg                   | fp register d18 |
| `(d19)`            | A64Reg                   | fp register d19 |
| `(d20)`            | A64Reg                   | fp register d20 |
| `(d21)`            | A64Reg                   | fp register d21 |
| `(d22)`            | A64Reg                   | fp register d22 |
| `(d23)`            | A64Reg                   | fp register d23 |
| `(d24)`            | A64Reg                   | fp register d24 |
| `(d25)`            | A64Reg                   | fp register d25 |
| `(d26)`            | A64Reg                   | fp register d26 |
| `(d27)`            | A64Reg                   | fp register d27 |
| `(d28)`            | A64Reg                   | fp register d28 |
| `(d29)`            | A64Reg                   | fp register d29 |
| `(d30)`            | A64Reg                   | fp register d30 |
| `(d31)`            | A64Reg                   | fp register d31 |
| `(s0)`             | A64Reg, MReg                   | fp register s0 |
| `(s1)`             | A64Reg, MReg                   | fp register s1 |
| `(s2)`             | A64Reg, MReg                   | fp register s2 |
| `(s3)`             | A64Reg, MReg                   | fp register s3 |
| `(s4)`             | A64Reg, MReg                   | fp register s4 |
| `(s5)`             | A64Reg, MReg                   | fp register s5 |
| `(s6)`             | A64Reg, MReg                   | fp register s6 |
| `(s7)`             | A64Reg, MReg                   | fp register s7 |
| `(s8)`             | A64Reg, MReg                   | fp register s8 |
| `(s9)`             | A64Reg, MReg                   | fp register s9 |
| `(s10)`            | A64Reg, MReg                   | fp register s10 |
| `(s11)`            | A64Reg, MReg                   | fp register s11 |
| `(s12)`            | A64Reg, MReg                   | fp register s12 |
| `(s13)`            | A64Reg, MReg                   | fp register s13 |
| `(s14)`            | A64Reg, MReg                   | fp register s14 |
| `(s15)`            | A64Reg, MReg                   | fp register s15 |
| `(s16)`            | A64Reg, MReg                   | fp register s16 |
| `(s17)`            | A64Reg, MReg                   | fp register s17 |
| `(s18)`            | A64Reg, MReg                   | fp register s18 |
| `(s19)`            | A64Reg, MReg                   | fp register s19 |
| `(s20)`            | A64Reg, MReg                   | fp register s20 |
| `(s21)`            | A64Reg, MReg                   | fp register s21 |
| `(s22)`            | A64Reg, MReg                   | fp register s22 |
| `(s23)`            | A64Reg, MReg                   | fp register s23 |
| `(s24)`            | A64Reg, MReg                   | fp register s24 |
| `(s25)`            | A64Reg, MReg                   | fp register s25 |
| `(s26)`            | A64Reg, MReg                   | fp register s26 |
| `(s27)`            | A64Reg, MReg                   | fp register s27 |
| `(s28)`            | A64Reg, MReg                   | fp register s28 |
| `(s29)`            | A64Reg, MReg                   | fp register s29 |
| `(s30)`            | A64Reg, MReg                   | fp register s30 |
| `(s31)`            | A64Reg, MReg                   | fp register s31 |
| `(fmov D S)`        | A64Inst, MInst                 | fp move (reg-reg / gpr<->fp bitcast) |
| `(fadd D S)`        | A64Inst, MInst                 | fp add (D = D + S) |
| `(fsub D S)`        | A64Inst, MInst                 | fp subtract (D = D - S) |
| `(fmul D S)`        | A64Inst, MInst                 | fp multiply (D = D * S) |
| `(fdiv D S)`        | A64Inst, MInst                 | fp divide (D = D / S) |
| `(fneg D)`          | A64Inst, MInst                 | fp negate (D = -D) |
| `(fcmp D S)`        | A64Inst, MInst                 | fp compare |
| `(fldr D S)`        | A64Inst, MInst                 | fp load register |
| `(fstr D S)`        | A64Inst, MInst                 | fp store register |
| `(scvtf D S)`       | A64Inst, MInst                 | signed int -> fp convert |
| `(ucvtf D S)`       | A64Inst, MInst                 | unsigned int -> fp convert |
| `(fcvtzs D S)`      | A64Inst, MInst                 | fp -> signed int convert (toward zero) |
| `(fcvtzu D S)`      | A64Inst, MInst                 | fp -> unsigned int convert (toward zero) |
| `(fcvt D S)`        | A64Inst                 | fp precision convert (f32<->f64) |
| `(fstp D1 D2 S O)`  | A64Inst                 | fp store pair (pre-indexed) |
| `(fldp D1 D2 S O)`  | A64Inst                 | fp load pair (post-indexed) |
| `(ldrb D B I)`      | A64Inst, MInst | load byte (zero-extend), register offset [B,I] |
| `(strb D B I)`      | A64Inst, MInst | store low byte, register offset [B,I] |
| `(rebind D T S)`    | X64Inst, A64Inst, MInst | bind a phys reg to a typed name, killing its prior tenant |
| `(withreg D T S ...)` | X64Inst, A64Inst, MInst | block-scoped rebind; auto-killed at block end |
| `(regs ...)`          | NifasmDecl                  | multi-register param/result location: `(regs (rdi) (rsi))` |
| `(bswap D N)`         | X64Inst                     | reverse byte order of D in place; `N` is the operand size in bits (32 or 64) |
| `(scope ...)`         | X64Inst, A64Inst, MInst | statement block with a reclaimable stack-slot arena: `(s)` locals declared inside are freed at scope end so sibling scopes reuse the frame bytes |
| `(popcnt D S N)`      | X64Inst                     | population count: D = number of set bits in S; `N` is the operand size in bits (32 or 64) |
| `(clz D S N)`         | A64Inst, MInst | count leading zeros: D = number of leading zero bits of S; `N` is the operand size in bits (32 or 64) |
| `(rbit D S N)`        | A64Inst, MInst | reverse bit order of S into D (with `clz` this is a count-trailing-zeros); `N` is the operand size in bits |
| `(rev D S N)`         | A64Inst, MInst | reverse byte order of S into D; `N` is the operand size in bits (32 or 64) |
| `(casejmp S T ...)`   | X64Inst                     | computed-goto case dispatch (`imul S,S,N; lea T,[rip+slots]; add T,S; jmp T`): the `(stmts ...)` children are the branch bodies, NOP-padded to the measured uniform slot size N, so no lookup table and no memory load. S holds the 0-based slot index; S and T are destroyed. Every branch must end in a terminating jump (the pad NOPs are never executed) and must not define a label at its very end |
| `(js L)`              | X64Inst                     | jump if sign (SF=1: the result was negative) |
| `(jns L)`             | X64Inst                     | jump if not sign (SF=0) |
| `(lenient)`           | NifasmDecl                  | proc pragma (after the clobber section): the body is MACHINE-PORTED code (e.g. distilled from gcc), so the structural disciplines are off for this one proc — backward jumps to labels are allowed (no `(loop)` required), registers may be used raw even when bound (params, r11), a bare `(call P)`/`(jmp P)` to a proc needs no `(prepare)`, and the type/clobber checks are skipped. The checks exist to catch code-GENERATOR bugs; ported code was already correct on the machine it came from |
| `(punpcklqdq D S)`    | X64Inst                     | interleave low quadwords: D = [D.lo, S.lo] (xmm registers only; `(punpcklqdq X X)` broadcasts X's low quadword to both halves) |
| `(movupd D S)`        | X64Inst                     | move unaligned packed double (xmm/mem either side; the access is inherently 16 bytes — the mem operand's scalar type is not consulted, matching the hardware) |
| `(movups D S)`        | X64Inst                     | move unaligned packed single (xmm/mem either side; 16-byte access like `movupd`) |
| `(addpd D S)`         | X64Inst                     | packed double add, 2 lanes (xmm registers only) |
| `(subpd D S)`         | X64Inst                     | packed double subtract, 2 lanes, `D = D - S` (xmm registers only) |
| `(mulpd D S)`         | X64Inst                     | packed double multiply, 2 lanes (xmm registers only) |
| `(addps D S)`         | X64Inst                     | packed single add, 4 lanes (xmm registers only) |
| `(subps D S)`         | X64Inst                     | packed single subtract, 4 lanes, `D = D - S` (xmm registers only) |
| `(mulps D S)`         | X64Inst                     | packed single multiply, 4 lanes (xmm registers only) |
| `(shufps D S N)`      | X64Inst                     | shuffle packed singles: each of D's 4 lanes picks a source lane by the 2-bit fields of immediate N (low two from D, high two from S); `(shufps X X 0)` broadcasts lane 0 to all 4 |
| `(repstosb)`          | X64Inst                     | repeat store byte string: fills `rcx` bytes at `[rdi]` with `al`, advancing `rdi`; `rcx` ends 0 (DF=0 per SysV) |
| `(repstosq)`          | X64Inst                     | repeat store qword string: fills `rcx` qwords at `[rdi]` with `rax`, advancing `rdi`; `rcx` ends 0 |
| `(fldrq D S)`         | A64Inst                     | load a 128-bit q register from memory (`ldr Qt, [Xn, #imm]`, imm a multiple of 16). `D` is spelled as the register's d/s tag — the q width is the instruction's, exactly as `movdqu`'s 16-byte access is on x64 |
| `(fstrq D S)`         | A64Inst                     | store a 128-bit q register: `(fstrq <mem> <fpreg>)`, operand order as `fstr` |
| `(vfadd D A B)`       | A64Inst                     | vector fp add, lane-wise (D = A + B): arrangement `.2d` when the registers are d-spelled, `.4s` when s-spelled |
| `(vfsub D A B)`       | A64Inst                     | vector fp subtract, lane-wise (D = A - B), arrangement as `vfadd` |
| `(vfmul D A B)`       | A64Inst                     | vector fp multiply, lane-wise (D = A * B), arrangement as `vfadd` |
| `(vfmla D A B)`       | A64Inst                     | vector fp fused multiply-add, lane-wise (D = D + A * B), arrangement as `vfadd` |
| `(vdup D S)`          | A64Inst                     | broadcast lane 0 of S to every lane of D (`dup Vd.2d, Vn.d[0]` when d-spelled, `.4s/.s[0]` when s-spelled) |
| `(veor D A B)`        | A64Inst                     | vector bitwise xor over all 16 bytes (`eor Vd.16b`); `(veor X X X)` zeroes X |
| `(vaddv D S)`         | A64Inst                     | horizontal fp add of S's lanes into the scalar D (`faddp Dd, Vn.2d` when d-spelled; `faddp Vd.4s, Vn.4s, Vn.4s` + `faddp Sd, Vd.2s` when s-spelled) |
| `(vgreq D S)`         | A64Inst                     | valgrind client request: `S` holds the address of the 6-word request block (`request, arg1 .. arg5`), `D` receives valgrind's answer — 0 when nothing intercepted the request, which is what a program NOT running under valgrind always sees. Expands to the fixed instruction sequence valgrind's JIT recognizes (four `ror x12` totalling a full 64-bit rotation, then the `orr x10, x10, x10` marker — architecturally a no-op, hence the zero cost when unobserved), wrapped in the moves that stage x3/x4 around it and stage the answer back out |
| `(bkpt N)`           | MInst                       | breakpoint / semihosting call; `(bkpt 171)` is `bkpt #0xAB`, the ARM semihosting entry on M-profile (operation in r0, parameter block in r1, result back in r0) |
| `(bx D)`             | MInst                       | branch and exchange to the address in D; `(bx (lr))` is the ordinary Thumb return |
| `(blx D)`            | MInst                       | indirect call through the address in D |
| `(mvn D S)`          | MInst                       | bitwise NOT (D = not S) |
| `(bic3 D A B)`       | MInst                       | 3-operand bit clear (D = A and not B) |
| `(adds3 D A B)`      | MInst                       | 3-operand add SETTING the flags — the low half of a 64-bit add |
| `(adcs3 D A B)`      | MInst                       | 3-operand add with carry, setting the flags — the high half of a 64-bit add |
| `(subs3 D A B)`      | MInst                       | 3-operand subtract setting the flags — the low half of a 64-bit subtract |
| `(sbcs3 D A B)`      | MInst                       | 3-operand subtract with borrow, setting the flags — the high half of a 64-bit subtract |
| `(mls D A B C)`      | MInst                       | multiply-subtract (D = C - A*B); ARMv7-M has no modulo, so `a mod b` is `sdiv` then `mls` |
| `(umull L H A B)`    | MInst                       | unsigned 64-bit product of A and B into the register pair L (low) / H (high) |
| `(smull L H A B)`    | MInst                       | signed 64-bit product of A and B into the register pair L (low) / H (high) |
| `(tst A B)`          | MInst                       | set the flags from A and B, discarding the result |
| `(uxtb D S)`         | MInst                       | zero-extend the low byte of S into D |
| `(sxtb D S)`         | MInst                       | sign-extend the low byte of S into D |
| `(uxth D S)`         | MInst                       | zero-extend the low halfword of S into D |
| `(sxth D S)`         | MInst                       | sign-extend the low halfword of S into D |
| `(ldrh D S)`         | MInst                       | load an unsigned halfword |
| `(strh D S)`         | MInst                       | store a halfword |
| `(ldrsb D S)`        | MInst                       | load a byte, sign-extended |
| `(ldrsh D S)`        | MInst                       | load a halfword, sign-extended |
| `(wfi)`              | MInst                       | wait for interrupt — the idle trap a bare-metal image ends on |
| `(dsb)`              | MInst                       | data synchronization barrier: nothing after it begins until every memory access before it has completed. Needed after writing a system register that changes how later instructions behave (CPACR, MPU) |
| `(isb)`              | MInst                       | instruction synchronization barrier: flush the pipeline so instructions fetched before a context-changing write are re-fetched. Required between enabling the FPU and the first floating-point instruction |
| `(other N ...)`       | -                           | escape header: the tag whose id no longer fits NIF's 9-bit tag field. `N` is an inline int carrying the real id out of nifcore's 28-bit escape space, and the remaining children are the node's own. Every row above that names EXACTLY ONE of `X64Inst`/`A64Inst` — i.e. one target's machine mnemonics, 282 of them — is spelled this way in the token buffer, which is what keeps the shared 511 for the cross-target vocabulary and makes a new target (Cortex-M, RISC-V) cost zero shared ids. Never written or read as text: `parse` folds `(movzx …)` into it and the serializers unfold it back, so both the NIF text and the binary token format are unchanged |
