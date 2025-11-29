| Tag                    | Enums                       |   Description |
|------------------------|-----------------------------|---------------|
| `(bool)`               | NifasmType                  | boolean type |
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
| `(s)`                  | X64Flag                 | stack slot location tag |
| `(ssize)`              | NifasmExpr                  | stack size expression |
| `(mov D S)`            | X64Inst                  | move instruction |
| `(lea D S)`            | X64Inst                  | load effective address |
| `(movapd D S)`         | X64Inst                  | move aligned packed double |
| `(movsd D S)`          | X64Inst                  | move scalar double |
| `(add D S)`            | X64Inst                  | add instruction |
| `(sub D S)`            | X64Inst                  | subtract instruction |
| `(mul S)`              | X64Inst                  | unsigned multiply |
| `(imul D S)`           | X64Inst                  | signed multiply |
| `(div D S R)`          | X64Inst                  | unsigned divide |
| `(idiv D S R)`         | X64Inst                  | signed divide |
| `(addsd D S)`          | X64Inst                  | add scalar double |
| `(subsd D S)`          | X64Inst                  | subtract scalar double |
| `(mulsd D S)`          | X64Inst                  | multiply scalar double |
| `(divsd D S)`          | X64Inst                  | divide scalar double |
| `(and D S)`            | X64Inst                  | bitwise and |
| `(or D S)`             | X64Inst                  | bitwise or |
| `(xor D S)`            | X64Inst                  | bitwise xor |
| `(shl D S)`            | X64Inst                  | shift left |
| `(shr D S)`            | X64Inst                  | shift right |
| `(sal D S)`            | X64Inst                  | shift arithmetic left |
| `(sar D S)`            | X64Inst                  | shift arithmetic right |
| `(inc O)`              | X64Inst                  | increment |
| `(dec O)`              | X64Inst                  | decrement |
| `(neg O)`              | X64Inst                  | negate |
| `(not O)`              | X64Inst                  | bitwise not |
| `(cmp D S)`            | X64Inst                  | compare |
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
| `(call T ...)`         | X64Inst                  | function call |
| `(ret)`                | X64Inst                  | return instruction |
| `(push O)`             | X64Inst                  | push to stack |
| `(pop O)`              | X64Inst                  | pop from stack |
| `(nop)`                | X64Inst                  | no operation |
| `(syscall)`            | X64Inst                  | system call |
| `(lab L)`              | X64Inst                  | label definition |
| `(ite ...)`            | X64Inst                  | if-then-else structure |
| `(loop ...)`           | X64Inst                  | loop structure |
| `(stmts ...)`          | X64Inst                  | statement block |
| `(cfvar D)`            | NifasmDecl                  | control flow variable declaration |
| `(jtrue ...)`          | X64Inst                  | set control flow variable(s) to true |
| `(dot B F)`            | NifasmExpr                  | field access |
| `(at B I)`             | NifasmExpr                  | array index |
| `(mem ...)`            | NifasmExpr                  | memory reference |
| `(rodata L S)`         | NifasmDecl                  | read-only data (string/bytes) |
| `(gvar D L T)`         | NifasmDecl                  | global variable |
| `(tvar D L T)`         | NifasmDecl                  | thread local variable |
| `(kill S)`             | X64Inst                  | kill variable |
| `(cast T E)`         | NifasmExpr                  | type cast |
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
