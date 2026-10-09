/**
 * legacy_plaintext_probe.cpp -- 旧明文路径复现（仅供对比取证，不进任何产物）
 *
 * 复刻改造前 httpPostRaw 的裸 socket 明文行为：
 *   - 对 host:port 建 TCP
 *   - 直接写 "POST <path> HTTP/1.1\r\nHost: ...\r\n\r\n<body>"
 *
 * 用途：与 tls_transport 的新实现做同一条链路上的字节级 A/B 对照，
 *       证明改造后出网字节里不再有 HTTP 明文（只有 TLS 记录）。
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char** argv) {
    const char* host = (argc > 1) ? argv[1] : "127.0.0.1";
    int port = (argc > 2) ? atoi(argv[2]) : 18444;
    const char* path = "/login";
    std::string postData = "kami=TEST-KAMI-1234&imei=0011223344556677&t=1770000000";

    struct hostent* he = gethostbyname(host);
    if (!he) { printf("dns fail\n"); return 1; }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { printf("socket fail\n"); return 1; }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    memcpy(&sa.sin_addr, he->h_addr, he->h_length);

    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        printf("connect fail\n");
        close(sock);
        return 1;
    }

    char req[1024];
    int n = snprintf(req, sizeof(req),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host, (unsigned)postData.size());
    std::string full(req, (size_t)n);
    full += postData;

    send(sock, full.data(), full.size(), 0);
    /* 只发不收, 立即退出 */
    close(sock);
    printf("sent %zu bytes (plaintext)\n", full.size());
    return 0;
}
