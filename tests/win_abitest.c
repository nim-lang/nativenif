#include <stdarg.h>
typedef struct { int a; } Small4;
typedef struct { int a, b; } Pair8;
typedef struct { long long a, b, c; } Big24;
typedef struct { unsigned char a, b, c; } Odd3;
typedef double (*Cb1)(double, Small4, double, Big24, double, long long, float, Pair8, Odd3);
typedef Big24 (*Cb2)(long long);
typedef Pair8 (*Cb3)(void);
typedef long long (*Cb4)(long long, long long, long long, long long, long long, double);

__declspec(dllexport) double c_one(double a, Small4 b, double c, Big24 d, double e, long long f,
                                   float g, Pair8 h, Odd3 i) {
  return a + c*2 + e*4 + g + (double)(d.a + d.b + d.c + f + b.a + h.a + h.b + i.a + i.b + i.c);
}
__declspec(dllexport) Big24 c_two(long long x) { Big24 r = {x, x*2, x*3}; return r; }
__declspec(dllexport) Pair8 c_three(void) { Pair8 r = {5, 6}; return r; }
__declspec(dllexport) long long c_four(long long a, long long b, long long c, long long d, long long e, double f) {
  return a - b + c - d + e + (long long)f;
}
/* the callbacks, called the way a Windows caller calls them */
__declspec(dllexport) int c_callbacks(Cb1 one, Cb2 two, Cb3 three, Cb4 four) {
  int score = 0;
  Small4 sm = {10}; Big24 bg = {100, 200, 300}; Pair8 pr = {3, 4}; Odd3 od = {1, 2, 3};
  if (one(1.5, sm, 2.25, bg, 0.5, 7, 0.25f, pr, od) == 638.25) score |= 1;
  Big24 r2 = two(11); if (r2.a + r2.b + r2.c == 66) score |= 2;
  Pair8 r3 = three(); if (r3.a * 10 + r3.b == 56) score |= 4;
  if (four(50, 20, 5, 3, 1, 8.0) == 41) score |= 8;
  return score;
}
/* callee-saved xmm6..15 across a callback: load, call, compare */
extern int xmm_check(Cb4 four);
__asm__(
  ".globl xmm_check\n"
  "xmm_check:\n"
  "  push %rbx\n  sub $0x30, %rsp\n"
  "  mov %rcx, %rbx\n"
  "  mov $0x1122334455667788, %rax\n  movq %rax, %xmm6\n  movq %rax, %xmm7\n  movq %rax, %xmm8\n"
  "  movq %rax, %xmm9\n  movq %rax, %xmm10\n  movq %rax, %xmm11\n  movq %rax, %xmm12\n"
  "  movq %rax, %xmm13\n  movq %rax, %xmm14\n  movq %rax, %xmm15\n"
  "  mov $50, %rcx\n  mov $20, %rdx\n  mov $5, %r8\n  mov $3, %r9\n"
  "  movq $1, 0x20(%rsp)\n  mov $0x4020000000000000, %rax\n  mov %rax, 0x28(%rsp)\n"
  "  call *%rbx\n"
  "  mov $0x1122334455667788, %rcx\n  xor %eax, %eax\n"
  "  movq %xmm6, %rdx\n  cmp %rcx, %rdx\n  jne 1f\n  movq %xmm11, %rdx\n  cmp %rcx, %rdx\n  jne 1f\n"
  "  movq %xmm15, %rdx\n  cmp %rcx, %rdx\n  jne 1f\n  mov $16, %eax\n"
  "1: add $0x30, %rsp\n  pop %rbx\n  ret\n");
__declspec(dllexport) int c_xmm(Cb4 four) { return xmm_check(four); }
__declspec(dllexport) int c_va(const char *fmt, ...) {
  /* 'i' = long long, 'd' = double: returns sum*2 as int so a half value shows */
  va_list ap; va_start(ap, fmt); double s = 0;
  for (const char *p = fmt; *p; ++p) s += (*p == 'd') ? va_arg(ap, double) : (double)va_arg(ap, long long);
  va_end(ap); return (int)(s * 2);
}
