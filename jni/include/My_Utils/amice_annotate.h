#pragma once
// L2 Amice 混淆注解（编译期属性；未加载 amice 插件时 clang 忽略，零运行时开销）
// 分级依据：L2_加密设计分析.md §3.1 / T3加密保护设计.md §3.1-3.2
//
//   AMICE_VMP       S 级：指令级虚拟化（VMP）
//   AMICE_FLATTEN_H A 级：Flatten(dominator) + BCF + IndirectBranch
//   AMICE_FLATTEN_B B 级：Flatten(basic) + BCF（一般不用，全局环境变量已覆盖）
//
// 注意：
//   1) 必须 noinline，否则函数被内联进调用者，注解失效；
//   2) VMP 需要 -fno-exceptions：否则跨函数调用在 IR 上是 invoke，amice 会静默跳过；
//   3) 对应 Pass 必须在 AMICE_PASS_ORDER 允许列表内，否则注解不生效。
#if defined(__clang__)
#  define AMICE_VMP         __attribute__((noinline, annotate("+vm_virtualize,vm_runtime_scope=func")))
#  define AMICE_FLATTEN_H   __attribute__((noinline, annotate("+flatten,flatten_mode=dominator,+bcf,+indirect_branch")))
#  define AMICE_FLATTEN_B   __attribute__((noinline, annotate("+flatten,flatten_mode=basic,+bcf")))
#  define AMICE_NOFLAT      __attribute__((annotate("-flatten,-bcf,-vm_virtualize")))
#else
#  define AMICE_VMP
#  define AMICE_FLATTEN_H
#  define AMICE_FLATTEN_B
#  define AMICE_NOFLAT
#endif
