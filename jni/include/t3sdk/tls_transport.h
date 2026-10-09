/**
 * tls_transport.h -- T3 SDK 的 TLS 传输层 (mbedTLS 3.6.4 静态链接)
 *
 * 背景: 原 httpPostRaw 是裸 socket 明文 HTTP, 且把 https:// 降级到 80 端口
 *       (t3sdk.cpp "HTTPS降级为HTTP（与C版本一致）")。实测 T3 六台服务器
 *       443 端口全部有合法 TLS 证书, 降级纯属原版 C 代码偷懒。
 *
 * 本模块把"裸 socket + 明文 HTTP"换成"mbedTLS 客户端 + 系统 CA 校验"。
 *
 * 信任模型 (两级):
 *   1. 硬门槛: TLS1.2/1.3 + 系统 CA 存储校验 + 主机名校验。
 *      只读系统 CA 目录 (/apex/com.android.conscrypt/cacerts 或
 *      /system/etc/security/cacerts), 【刻意不读】用户 CA 目录
 *      (/data/misc/keychain/cacerts-added)。效果: 攻击者就算把 Charles/Fiddler
 *      的根证书装进用户存储, 本客户端也永远不会信任它 -> 中间人工具直接出局。
 *   2. 颁发者白名单: 叶子证书的签发者必须在已知公共 CA 名单内。
 *      防的是 root 设备上攻击者往【系统】CA 存储里塞自签根证书的场景。
 *
 * 不锁叶子证书公钥: 实测 T3 六台服务器证书各自独立、90 天短命、CA 混用
 * TrustAsia 与 Let's Encrypt。锁叶子 = 每次续期全体客户端变砖。
 * 锁"颁发者"这一层既挡住了自签 MITM CA, 又能扛住 T3 的正常证书轮换。
 */

#ifndef T3_TLS_TRANSPORT_H
#define T3_TLS_TRANSPORT_H

#include <string>

namespace t3tls {

/**
 * 对 host:port 建立 TLS 连接, 发送 HTTP POST, 返回响应体。
 *
 * @param host      服务器域名 (同时用于 SNI 与主机名校验)
 * @param port      端口 (T3 用 443)
 * @param path      HTTP 路径, 形如 "/xxx"
 * @param postData  表单体 (application/x-www-form-urlencoded)
 * @param outBody   成功时写入 HTTP body
 * @return true  = TLS 握手 + HTTP 交换成功, 且状态码不是 408/5xx
 *         false = 任一步失败 (调用方据此切换备用线路)
 *
 * 线程安全: 内部串行化 (心跳线程与主线程共用一套 mbedTLS 上下文)。
 * 异常: 不抛异常 (工程全局 -fno-exceptions)。
 */
bool httpsPost(const std::string& host, int port, const std::string& path,
               const std::string& postData, std::string& outBody);

/** 释放缓存的 CA 链与 mbedTLS 上下文 (进程退出前可选调用)。 */
void releaseResources();

} /* namespace t3tls */

#endif /* T3_TLS_TRANSPORT_H */
