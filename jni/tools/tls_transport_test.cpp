/**
 * tls_transport_test.cpp -- tls_transport 桌面验证台
 *
 * 在 x86-64 Linux 上用同一份 tls_transport.cpp + mbedTLS 3.6.4 跑端到端验证,
 * 覆盖三条断言:
 *   A. 对真实 T3 服务器: TLS 握手 + 系统 CA 校验 + 颁发者白名单 全通过
 *   B. 对自签证书服务器: 必须被拒绝 (证明能挡住用户自装 CA 的中间人)
 *   C. 白名单被清空时: 对真实 T3 也必须被拒绝 (证明第二级门槛不是死代码)
 *
 * 编译见 tools/run_tls_test_host.sh
 */
#include "tls_transport.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

int main(int argc, char** argv) {
    const char* host = (argc > 1) ? argv[1] : "w.t3yanzheng.com";
    int port = (argc > 2) ? atoi(argv[2]) : 443;
    const char* expect = (argc > 3) ? argv[3] : "ok";   /* ok | reject */

    std::string body;
    bool ok = t3tls::httpsPost(host, port, "/", "probe=1", body);

    bool wantOk = (strcmp(expect, "ok") == 0);
    bool pass = (ok == wantOk);

    printf("[%s] host=%s:%d expect=%s got=%s bodylen=%zu\n",
           pass ? "PASS" : "FAIL", host, port, expect,
           ok ? "ok" : "reject", body.size());
    if (!body.empty()) {
        std::string head = body.substr(0, 140);
        for (size_t i = 0; i < head.size(); i++)
            if (head[i] == '\r' || head[i] == '\n') head[i] = ' ';
        printf("      body: %s\n", head.c_str());
    }
    t3tls::releaseResources();
    return pass ? 0 : 1;
}
