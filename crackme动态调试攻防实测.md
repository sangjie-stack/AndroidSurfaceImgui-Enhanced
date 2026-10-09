# crackme 动态调试攻防实测报告（2026-10-09）

> 攻击者视角全流程测试：拿自己的 crackme 挑战样本（B 档全混淆）当靶子，用 Frida 17.17.0（官方 server 部署于设备）+ capstone + 内存分析打一遍。**结论：动态调试能破到哪一步、卡在哪一步，全部实测。**

---

## 0. 攻击环境

- 官方 frida-server 17.17.0（kxmwp 魔改版协议不兼容已弃用）；spawn/attach/hook 全通
- 目标：`crackme.B_vmp.bin`（280KB：StringEncryption + verify 三段全 `+vm_virtualize` + 门禁汇总 `+vm_flatten`）
- 参考组：`crackme.A_base.bin`（7.2KB 无混淆，模拟"攻击者拿到源码级理解的捷径"）

## 1. 攻击实验矩阵（全部真机实测）

| # | 攻击 | 目标 | 结果 |
|---|---|---|---|
| 1 | Frida hook printf（错卡） | 直接截 FLAG 明文 | ❌ **FLAG 根本不产生**——错卡时内存里不存在 FLAG 明文，hook 不到不存在的东西 |
| 2 | 参考版 A + 正确卡 + printf hook | 验证输出链可截 | ✅ FLAG 明文被完整截获（`CRACKME-2026-SOLVED`）——**无 VMP 时动态调试必破** |
| 3 | **B 档 + 正确卡** + printf hook | 混淆版输出链 | ✅ 同样截获——**正确的卡密让 FLAG 在内存中现形，hook 输出函数即可截获** |
| 4 | **B 档 + 错卡 + 运行时改内存卡密**（攻击者从参考版/离线推演得知正确卡） | 绕过验证 | ✅ **成立**：在 strlen(card) 处把错误卡密改写成正确卡密 → 全部三段验证通过 → FLAG 输出并被截 |
| 5 | 伪造 verify 返回值（0xDEADBEEF 等 4 种） | patch 门禁拿 FLAG | ❌ **哨兵全部拦截**（`ACCESS DENIED`）——假 material 解出的 FLAG 前四字节对不上哨兵 |
| 6 | B 档二进制找 TARGET 常量（sbox_state/digest×4/csum/哨兵） | 静态提取校验值做离线爆破 | ❌ **全部 NOT FOUND**——常量被 VMP 吞进字节码，二进制里零痕迹 |

## 2. 攻防分水岭（核心发现）

**这个样本的强度不取决于"能不能 hook"（能，全都能 hook），而取决于攻击者手里有没有正确卡密：**

```
不知道卡密的攻击者（真破解场景）:
  ├─ 静态: TARGET 常量零痕迹（实验6）→ 无法离线爆破
  ├─ 动态: 错卡时 FLAG 不产生（实验1）→ hook 输出无意义
  ├─ patch: 改门禁返回值 → 哨兵拦截（实验5）→ 假 FLAG 不可用
  └─ 剩余路径: 逆 VMP 字节码还原算法 → 拿 TARGET 常量 → 离线推卡密
      = 需要 devirtualizer，成本即 "VM 逆向" 本身

知道卡密的攻击者（拿到过答案/从参考版推出）:
  └─ 改内存卡密（实验4）→ 直接过验证拿 FLAG
      = 防线全失, 因为验证本身是诚实的（它验证的就是"知道卡密"）
```

**实验 4 的教训（对挑战规则的重大影响）：** 我发了 `crackme_easy_reference.bin` 参考版——但参考版和挑战版**用的是同一张卡密**。攻击者在参考版上动态调试（hook 三段函数、dump TARGET 常量）就能离线推出卡密，然后在挑战版上改内存卡密直接过。**参考版与挑战版必须用不同卡密，或者干脆不发参考版。**

## 3. Frida 17 实操坑（给挑战者的"公平提示"素材）

- kxmwp 魔改 frida-server 17.17.1-dev 与官方 client 17.17.0 协议不兼容（`unable to communicate`）；官方 server 直接可用
- frida 17 API 大改：`Memory.readByteArray/readCString` 已移除，改 `ptr.readByteArray()` 实例方法；`Module.getExportByName` 移除，改 `module.enumerateExports()` 遍历
- B 档仅 11 个导入（printf/strlen/fgets/strncmp/__strlen_chk/__stack_chk_fail 等），静态可见——但这些全是 libc 边界，验证逻辑零痕迹

## 4. 挑战包修订（基于本次攻防）

1. **参考版换卡密**：`gen_target.py --card <另一张> --flag ...` 单独生成参考版参数——参考版只用于理解算法，不泄露挑战答案；
2. **README 增补公平提示**：frida 17 API 变化 + 推荐攻击面（诚实告知哨兵防线存在，避免纯撞墙）；
3. **判定补充**："改内存卡密"类攻击若发生在挑战版上且攻击者无法说明卡密来源 → 视为已从参考版泄露，判挑战包设计缺陷而非破解成功（本次实测即属此类）；
4. **真正的满分破解定义**：不接触正确卡密、不依赖参考版，仅凭 crackme.bin 输出 FLAG{...}——目前实测无人可达（需要逆 VMP 字节码）。

## 5. 最终强度评级（动态调试视角）

| 防线 | 抗 Frida hook | 抗 patch | 抗内存分析 | 抗离线推演 |
|---|---|---|---|---|
| 字符串加密（含 FLAG 密文） | ✅ 无明文可 hook | — | ✅ 扫不到 | ❌ 若拿到算法+常量可解 |
| VMP（三段验证函数） | ✅ 逻辑不在 native | ✅ 无分支可 NOP | ✅ 常量零痕迹 | ✅ 需 devirtualizer |
| 产物绑定（material→FLAG key） | — | ✅ 哨兵实测 4/4 拦截 | — | — |
| **卡密本身（知识型防线）** | ❌ 知道即破 | ❌ 同左 | ❌ 同左 | — |

**一句话：算法层（VMP+哨兵+密文）扛住了全部静态与伪造攻击；唯一的"破"来自知识泄漏（正确卡密/参考版同卡密）。这与真实卡密系统一致——系统强度再高，卡密本身泄露就是终点。挑战包按 §4 修订后即为完整的教学级对抗样本。**
