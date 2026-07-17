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
| `(arch x64/arm64)`     | NifasmDecl                  | architecture pragma |
| `(s)`                  | X64Flag                 | stack slot location tag |
| `(align N)`            | NifasmExpr                  | stack-slot alignment annotation (child of `(s)`) |
| `(ssize)`              | NifasmExpr                  | stack size expression |
| `(csize)`              | NifasmExpr                  | call stack size expression |
| `(arg S)`              | NifasmExpr                  | argument reference in prepare block |
| `(res S)`              | NifasmExpr                  | result reference in prepare block |
| `(prepare S ...)`      | X64Inst, A64Inst            | prepare block for function call |
| `(mov D S)`            | X64Inst, A64Inst         | move instruction |
| `(lea D S)`            | X64Inst, A64Inst         | load effective address |
| `(movapd D S)`         | X64Inst                  | move aligned packed double |
| `(movsd D S)`          | X64Inst                  | move scalar double |
| `(add D S)`            | X64Inst, A64Inst         | add instruction |
| `(sub D S)`            | X64Inst, A64Inst         | subtract instruction |
| `(mul S)`              | X64Inst, A64Inst         | unsigned multiply |
| `(imul D S)`           | X64Inst                  | signed multiply |
| `(div D S R)`          | X64Inst                  | unsigned divide |
| `(idiv D S R)`         | X64Inst                  | signed divide |
| `(sdiv D S)`           | A64Inst                  | signed divide |
| `(udiv D S)`           | A64Inst                  | unsigned divide |
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
| `(movfq D S)`          | X64Inst                  | move 64 bits between gpr and xmm |
| `(movfd D S)`          | X64Inst                  | move 32 bits between gpr and xmm |
| `(and D S)`            | X64Inst, A64Inst         | bitwise and |
| `(or D S)`             | X64Inst                  | bitwise or |
| `(orr D S)`            | A64Inst                  | bitwise or |
| `(xor D S)`            | X64Inst                  | bitwise xor |
| `(eor D S)`            | A64Inst                  | bitwise xor |
| `(shl D S)`            | X64Inst                  | shift left |
| `(lsl D S)`            | A64Inst                  | logical shift left |
| `(shr D S)`            | X64Inst                  | shift right |
| `(lsr D S)`            | A64Inst                  | logical shift right |
| `(sal D S)`            | X64Inst                  | shift arithmetic left |
| `(sar D S)`            | X64Inst                  | shift arithmetic right |
| `(asr D S)`            | A64Inst                  | arithmetic shift right |
| `(inc O)`              | X64Inst                  | increment |
| `(dec O)`              | X64Inst                  | decrement |
| `(neg O)`              | X64Inst, A64Inst         | negate |
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
| `(cmp D S)`            | X64Inst, A64Inst         | compare |
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
| `(call T ...)`         | X64Inst, A64Inst         | function call marker inside prepare |
| `(extcall)`            | X64Inst, A64Inst         | external call marker inside prepare |
| `(iat S)`              | X64Inst                  | indirect call through IAT (Import Address Table) |
| `(ret)`                | X64Inst, A64Inst         | return instruction |
| `(push O)`             | X64Inst                  | push to stack |
| `(pop O)`              | X64Inst                  | pop from stack |
| `(nop)`                | X64Inst, A64Inst         | no operation |
| `(syscall)`            | X64Inst                  | system call |
| `(svc N)`              | A64Inst                  | supervisor call (system call) |
| `(adr D L)`            | A64Inst                  | load address of label |
| `(ldr D S)`            | A64Inst                  | load register |
| `(str D S)`            | A64Inst                  | store register |
| `(stp D1 D2 S)`        | A64Inst                  | store pair |
| `(ldp D1 D2 S)`        | A64Inst                  | load pair |
| `(b L)`                | A64Inst                  | branch (unconditional jump) |
| `(bl L)`               | A64Inst                  | branch with link (function call) |
| `(beq L)`              | A64Inst                  | branch if equal |
| `(bne L)`              | A64Inst                  | branch if not equal |
| `(blt L)`              | A64Inst                  | branch if less than (signed) |
| `(ble L)`              | A64Inst                  | branch if less or equal (signed) |
| `(bgt L)`              | A64Inst                  | branch if greater than (signed) |
| `(bge L)`              | A64Inst                  | branch if greater or equal (signed) |
| `(blo L)`              | A64Inst                  | branch if lower (unsigned <) |
| `(bls L)`              | A64Inst                  | branch if lower or same (unsigned <=) |
| `(bhi L)`              | A64Inst                  | branch if higher (unsigned >) |
| `(bhs L)`              | A64Inst                  | branch if higher or same (unsigned >=) |
| `(cseleq D S1 S2)`     | A64Inst                  | conditional select: D = if equal then S1 else S2 |
| `(cselne D S1 S2)`     | A64Inst                  | conditional select: D = if not equal then S1 else S2 |
| `(csellt D S1 S2)`     | A64Inst                  | conditional select: D = if less than (signed) then S1 else S2 |
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
| `(lab L)`              | X64Inst, A64Inst         | label definition |
| `(ite ...)`            | X64Inst, A64Inst         | if-then-else structure |
| `(loop ...)`           | X64Inst, A64Inst         | loop structure |
| `(stmts ...)`          | X64Inst, A64Inst         | statement block |
| `(cfvar D)`            | NifasmDecl                  | control flow variable declaration |
| `(jtrue ...)`          | X64Inst, A64Inst            | set control flow variable(s) to true |
| `(dot B F)`            | NifasmExpr                  | field access |
| `(at B I)`             | NifasmExpr                  | array index |
| `(mem ...)`            | NifasmExpr                  | memory reference |
| `(rodata L S)`         | NifasmDecl                  | read-only data (string/bytes) |
| `(gvar D L T)`         | NifasmDecl                  | global variable |
| `(tvar D L T)`         | NifasmDecl                  | thread local variable |
| `(imp S)`              | NifasmDecl                  | import dynamic library |
| `(extproc D S)`        | NifasmDecl                  | external proc from imported library |
| `(syproc D ...)`       | NifasmDecl                  | system-call proc declaration (proctype + clobbers + number) |
| `(kill S)`             | X64Inst, A64Inst            | kill variable |
| `(cast T E)`         | NifasmExpr                  | type cast |
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
| `(r8)`               | X64Reg                   | register r8 |
| `(r9)`               | X64Reg                   | register r9 |
| `(r10)`              | X64Reg                   | register r10 |
| `(r11)`              | X64Reg                   | register r11 |
| `(r12)`              | X64Reg                   | register r12 |
| `(r13)`              | X64Reg                   | register r13 |
| `(r14)`              | X64Reg                   | register r14 |
| `(r15)`              | X64Reg                   | register r15 |
| `(r0)`               | X64Reg                   | register r0 (alias) |
| `(r1)`               | X64Reg                   | register r1 (alias) |
| `(r2)`               | X64Reg                   | register r2 (alias) |
| `(r3)`               | X64Reg                   | register r3 (alias) |
| `(r4)`               | X64Reg                   | register r4 (alias) |
| `(r5)`               | X64Reg                   | register r5 (alias) |
| `(r6)`               | X64Reg                   | register r6 (alias) |
| `(r7)`               | X64Reg                   | register r7 (alias) |
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
| `(sp)`               | A64Reg                   | stack pointer |
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
| `(lr)`               | A64Reg                   | link register (alias for x30) |
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
| `(s0)`             | A64Reg                   | fp register s0 |
| `(s1)`             | A64Reg                   | fp register s1 |
| `(s2)`             | A64Reg                   | fp register s2 |
| `(s3)`             | A64Reg                   | fp register s3 |
| `(s4)`             | A64Reg                   | fp register s4 |
| `(s5)`             | A64Reg                   | fp register s5 |
| `(s6)`             | A64Reg                   | fp register s6 |
| `(s7)`             | A64Reg                   | fp register s7 |
| `(s8)`             | A64Reg                   | fp register s8 |
| `(s9)`             | A64Reg                   | fp register s9 |
| `(s10)`            | A64Reg                   | fp register s10 |
| `(s11)`            | A64Reg                   | fp register s11 |
| `(s12)`            | A64Reg                   | fp register s12 |
| `(s13)`            | A64Reg                   | fp register s13 |
| `(s14)`            | A64Reg                   | fp register s14 |
| `(s15)`            | A64Reg                   | fp register s15 |
| `(s16)`            | A64Reg                   | fp register s16 |
| `(s17)`            | A64Reg                   | fp register s17 |
| `(s18)`            | A64Reg                   | fp register s18 |
| `(s19)`            | A64Reg                   | fp register s19 |
| `(s20)`            | A64Reg                   | fp register s20 |
| `(s21)`            | A64Reg                   | fp register s21 |
| `(s22)`            | A64Reg                   | fp register s22 |
| `(s23)`            | A64Reg                   | fp register s23 |
| `(s24)`            | A64Reg                   | fp register s24 |
| `(s25)`            | A64Reg                   | fp register s25 |
| `(s26)`            | A64Reg                   | fp register s26 |
| `(s27)`            | A64Reg                   | fp register s27 |
| `(s28)`            | A64Reg                   | fp register s28 |
| `(s29)`            | A64Reg                   | fp register s29 |
| `(s30)`            | A64Reg                   | fp register s30 |
| `(s31)`            | A64Reg                   | fp register s31 |
| `(fmov D S)`        | A64Inst                 | fp move (reg-reg / gpr<->fp bitcast) |
| `(fadd D S)`        | A64Inst                 | fp add (D = D + S) |
| `(fsub D S)`        | A64Inst                 | fp subtract (D = D - S) |
| `(fmul D S)`        | A64Inst                 | fp multiply (D = D * S) |
| `(fdiv D S)`        | A64Inst                 | fp divide (D = D / S) |
| `(fneg D)`          | A64Inst                 | fp negate (D = -D) |
| `(fcmp D S)`        | A64Inst                 | fp compare |
| `(fldr D S)`        | A64Inst                 | fp load register |
| `(fstr D S)`        | A64Inst                 | fp store register |
| `(scvtf D S)`       | A64Inst                 | signed int -> fp convert |
| `(ucvtf D S)`       | A64Inst                 | unsigned int -> fp convert |
| `(fcvtzs D S)`      | A64Inst                 | fp -> signed int convert (toward zero) |
| `(fcvtzu D S)`      | A64Inst                 | fp -> unsigned int convert (toward zero) |
| `(fcvt D S)`        | A64Inst                 | fp precision convert (f32<->f64) |
| `(fstp D1 D2 S O)`  | A64Inst                 | fp store pair (pre-indexed) |
| `(fldp D1 D2 S O)`  | A64Inst                 | fp load pair (post-indexed) |
| `(ldrb D B I)`      | A64Inst                 | load byte (zero-extend), register offset [B,I] |
| `(strb D B I)`      | A64Inst                 | store low byte, register offset [B,I] |
| `(rebind D T S)`    | X64Inst, A64Inst        | bind a phys reg to a typed name, killing its prior tenant |
| `(withreg D T S ...)` | X64Inst, A64Inst      | block-scoped rebind; auto-killed at block end |
| `(regs ...)`          | NifasmDecl                  | multi-register param/result location: `(regs (rdi) (rsi))` |
| `(bswap D)`           | X64Inst                     | reverse byte order (BSWAP r32/r64; `__builtin_bswap*`) |
| `(scope ...)`         | X64Inst, A64Inst            | statement block with a reclaimable stack-slot arena: `(s)` locals declared inside are freed at scope end so sibling scopes reuse the frame bytes |
