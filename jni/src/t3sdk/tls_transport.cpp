/**
 * tls_transport.cpp -- T3 SDK 的 TLS 传输层实现 (mbedTLS 3.6.4)
 * 设计说明见 include/t3sdk/tls_transport.h
 *
 * 编译约束:
 *   - 工程全局 -fno-exceptions / -fno-rtti 兼容: 本文件不抛异常, 全部错误码返回
 *   - arm64-v8a, APP_PLATFORM=android-22
 *   - 链接 mbedtls / mbedx509 / mbedcrypto 三个静态库
 */

#include "tls_transport.h"
#include "amice_annotate.h"   // L2: amice 混淆注解

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <string>
#include <mutex>
#include <dirent.h>

namespace t3tls {
namespace {

/* ============================================================
 *  颁发者白名单
 *  实测 T3 当前签发者: TrustAsia DV TLS RSA CA 2024 / Let's Encrypt YR1/YR2。
 *  名单刻意放宽到主流公共 CA —— 目的是挡住"自签 MITM 根证书"(任何自建 CA 都不在
 *  名单内), 而不是锁死 T3 的证书供应商。T3 换 CA 时不需要改客户端。
 * ============================================================ */
const char* const kIssuerAllowlist[] = {
    "Let's Encrypt",
    "TrustAsia",
    "DigiCert",
    "Sectigo",
    "USERTrust",
    "COMODO",
    "GlobalSign",
    "Google Trust Services",
    "ZeroSSL",
    "Buypass",
    "SSL.com",
    "Actalis",
    "Certum",
    "Entrust",
    "Amazon",
    "GoDaddy",
    "Starfield",
    "IdenTrust",
    "HARICA",
    "SecureTrust",
    "Certigna",
    nullptr
};

/* 系统 CA 目录。刻意不含 /data/misc/keychain/cacerts-added (用户 CA 存储):
 * 用户装进手机的任何根证书都不被本客户端信任 —— 这是挡住
 * Charles / Fiddler / Burp / mitmproxy 的关键。 */
const char* const kSystemCaDirs[] = {
    "/apex/com.android.conscrypt/cacerts",  /* Android 14+: CA 存储迁到 conscrypt APEX */
    "/system/etc/security/cacerts",         /* Android 4.0 ~ 13 */
    "/etc/ssl/certs",                       /* 桌面 Linux 调试用 */
    nullptr
};

const int kConnectTimeoutSec = 3;
const int kIoSocketTimeoutSec = 7;
const size_t kMaxCaFileBytes = 64 * 1024;

/* mbedTLS 的网络错误码定义在 net_sockets.h, 但本项目未启用 MBEDTLS_NET_C
 * (自带 socket 实现), 故在此直接取等价值。BIO 回调只需返回负值即被 mbedTLS
 * 视为致命错误, 数值与上游 net_sockets.h 保持一致以便日志对照。 */
const int kErrNetSendFailed = -0x004E;   /* MBEDTLS_ERR_NET_SEND_FAILED */
const int kErrNetRecvFailed = -0x004C;   /* MBEDTLS_ERR_NET_RECV_FAILED */

/* ============================================================
 *  全局状态 (受 mutex 保护; 心跳线程与主线程共用)
 * ============================================================ */
struct TlsState {
    std::mutex mtx;
    bool inited = false;
    bool caLoaded = false;
    int caCount = 0;
    mbedtls_x509_crt ca;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_config conf;
};

TlsState& state() {
    static TlsState s;
    return s;
}

/* ============================================================
 *  CA 加载
 * ============================================================ */
int loadCaFromDir(mbedtls_x509_crt* ca, const char* dir) {
    DIR* d = opendir(dir);
    if (!d) return -1;

    /* static 缓冲: 避免 64KB 栈帧; 调用点已持有互斥锁, 无重入风险 */
    static unsigned char buf[kMaxCaFileBytes + 1];
    int count = 0;
    struct dirent* ent;
    while ((ent = readdir(d)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        char path[512];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        if (n <= 0 || n >= (int)sizeof(path)) continue;

        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        if (st.st_size <= 0 || (size_t)st.st_size > kMaxCaFileBytes) continue;

        FILE* f = fopen(path, "rb");
        if (!f) continue;
        size_t got = fread(buf, 1, kMaxCaFileBytes, f);
        fclose(f);
        if (got == 0) continue;
        buf[got] = '\0';
        /* PEM 解析要求长度含结尾 NUL */
        if (mbedtls_x509_crt_parse(ca, buf, got + 1) == 0) count++;
    }
    closedir(d);
    return count;
}

bool ensureInitedLocked() {
    TlsState& s = state();
    if (s.inited) return true;

    mbedtls_x509_crt_init(&s.ca);
    mbedtls_entropy_init(&s.entropy);
    mbedtls_ctr_drbg_init(&s.drbg);
    mbedtls_ssl_config_init(&s.conf);

    /* mbedTLS 3.6 默认开启 MBEDTLS_USE_PSA_CRYPTO, 必须先初始化 PSA 子系统 */
    if (psa_crypto_init() != PSA_SUCCESS) return false;

    static const char kPers[] = "t3tls-drbg";
    if (mbedtls_ctr_drbg_seed(&s.drbg, mbedtls_entropy_func, &s.entropy,
                              (const unsigned char*)kPers, sizeof(kPers) - 1) != 0) {
        return false;
    }

    for (int i = 0; kSystemCaDirs[i] != nullptr && !s.caLoaded; i++) {
        int c = loadCaFromDir(&s.ca, kSystemCaDirs[i]);
        if (c > 0) {
            s.caLoaded = true;
            s.caCount = c;
        }
    }
    if (!s.caLoaded) return false;

    if (mbedtls_ssl_config_defaults(&s.conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        return false;
    }
    /* 硬门槛: 证书链必须验通, 否则握手直接失败 */
    mbedtls_ssl_conf_authmode(&s.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&s.conf, &s.ca, nullptr);
    mbedtls_ssl_conf_rng(&s.conf, mbedtls_ctr_drbg_random, &s.drbg);
    /* 最低 TLS1.2 (配置里已移除 TLS1.0/1.1) */
    mbedtls_ssl_conf_min_tls_version(&s.conf, MBEDTLS_SSL_VERSION_TLS1_2);

    s.inited = true;
    return true;
}

/* ============================================================
 *  TCP 连接 (带超时)
 * ============================================================ */
int connectTcp(const char* host, int port) {
    char portStr[16];
    snprintf(portStr, sizeof(portStr), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = nullptr;
    if (getaddrinfo(host, portStr, &hints, &res) != 0 || res == nullptr) return -1;

    int fd = -1;
    for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(fd);
            fd = -1;
            continue;
        }

        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc < 0 && errno != EINPROGRESS) {
            close(fd);
            fd = -1;
            continue;
        }
        if (rc < 0) {
            fd_set ws;
            FD_ZERO(&ws);
            FD_SET(fd, &ws);
            struct timeval tv;
            tv.tv_sec = kConnectTimeoutSec;
            tv.tv_usec = 0;
            rc = select(fd + 1, nullptr, &ws, nullptr, &tv);
            if (rc <= 0) {
                close(fd);
                fd = -1;
                continue;
            }
            int soErr = 0;
            socklen_t soLen = sizeof(soErr);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soErr, &soLen) != 0 || soErr != 0) {
                close(fd);
                fd = -1;
                continue;
            }
        }

        /* 恢复阻塞 + 读写超时, 交给 mbedTLS 的同步 BIO 回调 */
        if (fcntl(fd, F_SETFL, flags) < 0) {
            close(fd);
            fd = -1;
            continue;
        }
        struct timeval iotv;
        iotv.tv_sec = kIoSocketTimeoutSec;
        iotv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &iotv, sizeof(iotv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &iotv, sizeof(iotv));
        break;
    }
    freeaddrinfo(res);
    return fd;
}

/* ---- mbedTLS BIO 回调 ----
 * 超时 (EAGAIN) 必须映射成 MBEDTLS_ERR_SSL_TIMEOUT 而不是 WANT_READ,
 * 否则 mbedTLS 会无限重试 -> 请求挂死。 */
int bioSend(void* ctx, const unsigned char* buf, size_t len) {
    int fd = *(int*)ctx;
    ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_TIMEOUT;
        if (errno == EINTR) return MBEDTLS_ERR_SSL_WANT_WRITE;
        return kErrNetSendFailed;
    }
    return (int)n;
}

int bioRecv(void* ctx, unsigned char* buf, size_t len) {
    int fd = *(int*)ctx;
    ssize_t n = recv(fd, buf, len, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_TIMEOUT;
        if (errno == EINTR) return MBEDTLS_ERR_SSL_WANT_READ;
        return kErrNetRecvFailed;
    }
    if (n == 0) return MBEDTLS_ERR_SSL_CONN_EOF;
    return (int)n;
}

/* ============================================================
 *  颁发者白名单校验 (第二级防线)
 * ============================================================ */
bool issuerAllowed(const mbedtls_x509_crt* leaf) {
    if (leaf == nullptr) return false;
    char dn[512];
    int n = mbedtls_x509_dn_gets(dn, sizeof(dn), &leaf->issuer);
    if (n <= 0) return false;

    for (int i = 0; kIssuerAllowlist[i] != nullptr; i++) {
        if (strstr(dn, kIssuerAllowlist[i]) != nullptr) return true;
    }
    return false;
}

/* ============================================================
 *  HTTP 响应处理
 * ============================================================ */
/* Content-Length 完整则提前结束读取, 不等服务器关连接 (防止 keep-alive 挂到超时) */
bool bodyComplete(const std::string& resp) {
    size_t hdrEnd = resp.find("\r\n\r\n");
    if (hdrEnd == std::string::npos) return false;
    size_t clPos = resp.find("Content-Length:");
    if (clPos == std::string::npos) return false;
    if (clPos > hdrEnd) return false;
    long cl = strtol(resp.c_str() + clPos + 15, nullptr, 10);
    if (cl < 0) return false;
    return (long)(resp.size() - hdrEnd - 4) >= cl;
}

int parseStatus(const std::string& resp) {
    size_t lineEnd = resp.find("\r\n");
    if (lineEnd == std::string::npos) return 0;
    const char* p = resp.c_str();
    /* "HTTP/1.1 200 OK" -> 跳过版本与空格 */
    const char* sp = strchr(p, ' ');
    if (!sp) return 0;
    return atoi(sp + 1);
}

} /* anonymous namespace */

/* ============================================================
 *  对外接口
 * ============================================================ */
AMICE_FLATTEN_H /*L2AMICE*/
bool httpsPost(const std::string& host, int port, const std::string& path,
               const std::string& postData, std::string& outBody) {
    outBody.clear();
    if (host.empty() || path.empty()) return false;

    TlsState& s = state();
    std::lock_guard<std::mutex> lock(s.mtx);   /* 串行化整个会话 (共享 drbg/config) */

    if (!ensureInitedLocked()) return false;

    int fd = connectTcp(host.c_str(), port);
    if (fd < 0) return false;

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);

    bool ok = false;
    do {
        if (mbedtls_ssl_setup(&ssl, &s.conf) != 0) break;
        /* SNI + 主机名校验 (mbedTLS 会比对 CN/SAN, 不匹配则 verify 失败) */
        if (mbedtls_ssl_set_hostname(&ssl, host.c_str()) != 0) break;
        /* mbedTLS 3.x: mbedtls_ssl_set_bio 返回 void (2.x 返回 int) */
        mbedtls_ssl_set_bio(&ssl, &fd, bioSend, bioRecv, nullptr);

        int ret = mbedtls_ssl_handshake(&ssl);
        if (ret != 0) break;

        /* 一级门槛复核: 证书链 + 主机名 */
        uint32_t vr = mbedtls_ssl_get_verify_result(&ssl);
        if (vr != 0) break;

        /* 二级门槛: 颁发者白名单 */
        const mbedtls_x509_crt* peer = mbedtls_ssl_get_peer_cert(&ssl);
        if (!issuerAllowed(peer)) break;

        /* ---- 组装并发送 HTTP 请求 ---- */
        char head[512];
        int headLen = snprintf(head, sizeof(head),
            "POST %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: %u\r\n"
            "Connection: close\r\n"
            "\r\n",
            path.c_str(), host.c_str(), (unsigned)postData.size());
        if (headLen <= 0 || headLen >= (int)sizeof(head)) break;

        std::string req(head, (size_t)headLen);
        req += postData;

        size_t sent = 0;
        bool writeOk = true;
        while (sent < req.size()) {
            ret = mbedtls_ssl_write(&ssl, (const unsigned char*)req.data() + sent,
                                    req.size() - sent);
            if (ret > 0) {
                sent += (size_t)ret;
                continue;
            }
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            writeOk = false;
            break;
        }
        if (!writeOk) break;

        /* ---- 读取响应 ---- */
        std::string resp;
        char buf[4096];
        while (true) {
            ret = mbedtls_ssl_read(&ssl, (unsigned char*)buf, sizeof(buf));
            if (ret > 0) {
                resp.append(buf, (size_t)ret);
                if (bodyComplete(resp)) break;
                continue;
            }
            if (ret == 0) break;                                    /* 对端正常关闭 */
            if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            break;                                                  /* 超时/错误: 用已收到的数据 */
        }
        if (resp.empty()) break;

        /* 408/5xx 视为线路故障, 交由调用方切换备用服务器 (与原实现语义一致) */
        int status = parseStatus(resp);
        if (status == 408 || status >= 500) break;

        size_t bodyPos = resp.find("\r\n\r\n");
        if (bodyPos != std::string::npos) outBody = resp.substr(bodyPos + 4);
        else outBody = resp;

        ok = true;
        mbedtls_ssl_close_notify(&ssl);
    } while (false);

    mbedtls_ssl_free(&ssl);
    close(fd);
    return ok;
}

void releaseResources() {
    TlsState& s = state();
    std::lock_guard<std::mutex> lock(s.mtx);
    if (!s.inited) return;
    mbedtls_ssl_config_free(&s.conf);
    mbedtls_ctr_drbg_free(&s.drbg);
    mbedtls_entropy_free(&s.entropy);
    mbedtls_x509_crt_free(&s.ca);
    s.inited = false;
    s.caLoaded = false;
}

} /* namespace t3tls */
