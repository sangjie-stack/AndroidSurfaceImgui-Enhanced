/**
 * T3验证SDK - C++版本实现
 * 纯C++实现，不依赖OpenSSL
 */

#include "amice_annotate.h"   //L2: amice 混淆注解
#include "t3sdk.h"
#include "obfuscate.h" /*L1: PEM定界符编译期加密*/
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cctype>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include <random>

/* 平台检测 */
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
    #include <iphlpapi.h>
#else
    #include <sys/socket.h>
    #include <sys/time.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <cerrno>
    #include <sys/ioctl.h>
    #include <net/if.h>
    #ifdef __APPLE__
        #include <sys/sysctl.h>
        #include <net/if_dl.h>
    #else
        #include <linux/if_packet.h>
    #endif
#endif

/* ---- L2: 异常自由化（amice VMP/Flatten 前置条件）----
   C++ 异常关键字 try / catch / throw 会在 IR 里生成 invoke + landingpad，amice 明确拒绝这类函数。
   本文件所有异常原本都在文件内被 catch，故改为"错误槽 + 显式检查"，语义等价。*/
/* L2-FIX: 错误槽改为 thread_local。
   原因: 心跳线程(heartbeatThread)与主线程都会调用 SDK, 普通 static 会被并发读写
   (原 try/catch 版本每个函数各自持栈上异常对象, 无共享状态, 无此问题)。
   同时新增 t3_clear_error(): 每个"可能置错的内部助手"入口先清空, 使错误槽永远只
   反映"最近一次助手调用"的结果, 等价恢复原 try/catch 的函数级作用域隔离。*/
static thread_local std::string g_t3_error;
static inline void t3_raise(const char* msg) { g_t3_error = msg; }
static inline bool t3_failed() { return !g_t3_error.empty(); }
static inline void t3_clear_error() { g_t3_error.clear(); }
static inline std::string t3_take_error() { std::string e = g_t3_error; g_t3_error.clear(); return e; }
static inline std::string t3_take_error_or(const char* dflt) { std::string e = t3_take_error(); return e.empty() ? dflt : e; }

/* ========== MD5算法实现 ========== */
namespace {

struct MD5Context {
    uint32_t state[4];
    uint32_t count[2];
    unsigned char buffer[64];
};

#define MD5_S11 7
#define MD5_S12 12
#define MD5_S13 17
#define MD5_S14 22
#define MD5_S21 5
#define MD5_S22 9
#define MD5_S23 14
#define MD5_S24 20
#define MD5_S31 4
#define MD5_S32 11
#define MD5_S33 16
#define MD5_S34 23
#define MD5_S41 6
#define MD5_S42 10
#define MD5_S43 15
#define MD5_S44 21

#define MD5_F(x,y,z) (((x)&(y))|((~x)&(z)))
#define MD5_G(x,y,z) (((x)&(z))|((y)&(~z)))
#define MD5_H(x,y,z) ((x)^(y)^(z))
#define MD5_I(x,y,z) ((y)^((x)|(~z)))
#define MD5_ROL(x,n) (((x)<<(n))|((x)>>(32-(n))))

#define MD5_FF(a,b,c,d,x,s,ac) { (a)+=MD5_F((b),(c),(d))+(x)+(uint32_t)(ac); (a)=MD5_ROL((a),(s)); (a)+=(b); }
#define MD5_GG(a,b,c,d,x,s,ac) { (a)+=MD5_G((b),(c),(d))+(x)+(uint32_t)(ac); (a)=MD5_ROL((a),(s)); (a)+=(b); }
#define MD5_HH(a,b,c,d,x,s,ac) { (a)+=MD5_H((b),(c),(d))+(x)+(uint32_t)(ac); (a)=MD5_ROL((a),(s)); (a)+=(b); }
#define MD5_II(a,b,c,d,x,s,ac) { (a)+=MD5_I((b),(c),(d))+(x)+(uint32_t)(ac); (a)=MD5_ROL((a),(s)); (a)+=(b); }

static void md5Encode(unsigned char *out, const uint32_t *in, unsigned int len) {
    for (unsigned int i=0,j=0; j<len; i++,j+=4) {
        out[j]=(unsigned char)(in[i]&0xff);
        out[j+1]=(unsigned char)((in[i]>>8)&0xff);
        out[j+2]=(unsigned char)((in[i]>>16)&0xff);
        out[j+3]=(unsigned char)((in[i]>>24)&0xff);
    }
}

static void md5Decode(uint32_t *out, const unsigned char *in, unsigned int len) {
    for (unsigned int i=0,j=0; j<len; i++,j+=4)
        out[i]=((uint32_t)in[j])|(((uint32_t)in[j+1])<<8)|(((uint32_t)in[j+2])<<16)|(((uint32_t)in[j+3])<<24);
}

AMICE_FLATTEN_H /*L2AMICE*/
static void md5Transform(uint32_t state[4], const unsigned char block[64]) {
    uint32_t a=state[0],b=state[1],c=state[2],d=state[3],x[16];
    md5Decode(x,block,64);
    MD5_FF(a,b,c,d,x[0],MD5_S11,0xd76aa478); MD5_FF(d,a,b,c,x[1],MD5_S12,0xe8c7b756);
    MD5_FF(c,d,a,b,x[2],MD5_S13,0x242070db); MD5_FF(b,c,d,a,x[3],MD5_S14,0xc1bdceee);
    MD5_FF(a,b,c,d,x[4],MD5_S11,0xf57c0faf); MD5_FF(d,a,b,c,x[5],MD5_S12,0x4787c62a);
    MD5_FF(c,d,a,b,x[6],MD5_S13,0xa8304613); MD5_FF(b,c,d,a,x[7],MD5_S14,0xfd469501);
    MD5_FF(a,b,c,d,x[8],MD5_S11,0x698098d8); MD5_FF(d,a,b,c,x[9],MD5_S12,0x8b44f7af);
    MD5_FF(c,d,a,b,x[10],MD5_S13,0xffff5bb1); MD5_FF(b,c,d,a,x[11],MD5_S14,0x895cd7be);
    MD5_FF(a,b,c,d,x[12],MD5_S11,0x6b901122); MD5_FF(d,a,b,c,x[13],MD5_S12,0xfd987193);
    MD5_FF(c,d,a,b,x[14],MD5_S13,0xa679438e); MD5_FF(b,c,d,a,x[15],MD5_S14,0x49b40821);
    MD5_GG(a,b,c,d,x[1],MD5_S21,0xf61e2562); MD5_GG(d,a,b,c,x[6],MD5_S22,0xc040b340);
    MD5_GG(c,d,a,b,x[11],MD5_S23,0x265e5a51); MD5_GG(b,c,d,a,x[0],MD5_S24,0xe9b6c7aa);
    MD5_GG(a,b,c,d,x[5],MD5_S21,0xd62f105d); MD5_GG(d,a,b,c,x[10],MD5_S22,0x2441453);
    MD5_GG(c,d,a,b,x[15],MD5_S23,0xd8a1e681); MD5_GG(b,c,d,a,x[4],MD5_S24,0xe7d3fbc8);
    MD5_GG(a,b,c,d,x[9],MD5_S21,0x21e1cde6); MD5_GG(d,a,b,c,x[14],MD5_S22,0xc33707d6);
    MD5_GG(c,d,a,b,x[3],MD5_S23,0xf4d50d87); MD5_GG(b,c,d,a,x[8],MD5_S24,0x455a14ed);
    MD5_GG(a,b,c,d,x[13],MD5_S21,0xa9e3e905); MD5_GG(d,a,b,c,x[2],MD5_S22,0xfcefa3f8);
    MD5_GG(c,d,a,b,x[7],MD5_S23,0x676f02d9); MD5_GG(b,c,d,a,x[12],MD5_S24,0x8d2a4c8a);
    MD5_HH(a,b,c,d,x[5],MD5_S31,0xfffa3942); MD5_HH(d,a,b,c,x[8],MD5_S32,0x8771f681);
    MD5_HH(c,d,a,b,x[11],MD5_S33,0x6d9d6122); MD5_HH(b,c,d,a,x[14],MD5_S34,0xfde5380c);
    MD5_HH(a,b,c,d,x[1],MD5_S31,0xa4beea44); MD5_HH(d,a,b,c,x[4],MD5_S32,0x4bdecfa9);
    MD5_HH(c,d,a,b,x[7],MD5_S33,0xf6bb4b60); MD5_HH(b,c,d,a,x[10],MD5_S34,0xbebfbc70);
    MD5_HH(a,b,c,d,x[13],MD5_S31,0x289b7ec6); MD5_HH(d,a,b,c,x[0],MD5_S32,0xeaa127fa);
    MD5_HH(c,d,a,b,x[3],MD5_S33,0xd4ef3085); MD5_HH(b,c,d,a,x[6],MD5_S34,0x4881d05);
    MD5_HH(a,b,c,d,x[9],MD5_S31,0xd9d4d039); MD5_HH(d,a,b,c,x[12],MD5_S32,0xe6db99e5);
    MD5_HH(c,d,a,b,x[15],MD5_S33,0x1fa27cf8); MD5_HH(b,c,d,a,x[2],MD5_S34,0xc4ac5665);
    MD5_II(a,b,c,d,x[0],MD5_S41,0xf4292244); MD5_II(d,a,b,c,x[7],MD5_S42,0x432aff97);
    MD5_II(c,d,a,b,x[14],MD5_S43,0xab9423a7); MD5_II(b,c,d,a,x[5],MD5_S44,0xfc93a039);
    MD5_II(a,b,c,d,x[12],MD5_S41,0x655b59c3); MD5_II(d,a,b,c,x[3],MD5_S42,0x8f0ccc92);
    MD5_II(c,d,a,b,x[10],MD5_S43,0xffeff47d); MD5_II(b,c,d,a,x[1],MD5_S44,0x85845dd1);
    MD5_II(a,b,c,d,x[8],MD5_S41,0x6fa87e4f); MD5_II(d,a,b,c,x[15],MD5_S42,0xfe2ce6e0);
    MD5_II(c,d,a,b,x[6],MD5_S43,0xa3014314); MD5_II(b,c,d,a,x[13],MD5_S44,0x4e0811a1);
    MD5_II(a,b,c,d,x[4],MD5_S41,0xf7537e82); MD5_II(d,a,b,c,x[11],MD5_S42,0xbd3af235);
    MD5_II(c,d,a,b,x[2],MD5_S43,0x2ad7d2bb); MD5_II(b,c,d,a,x[9],MD5_S44,0xeb86d391);
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    memset(x,0,sizeof(x));
}

static void md5Init(MD5Context *ctx) {
    ctx->count[0]=ctx->count[1]=0;
    ctx->state[0]=0x67452301; ctx->state[1]=0xefcdab89;
    ctx->state[2]=0x98badcfe; ctx->state[3]=0x10325476;
}

AMICE_FLATTEN_H /*L2AMICE*/
static void md5Update(MD5Context *ctx, const unsigned char *input, unsigned int len) {
    unsigned int i,idx,partLen;
    idx=(unsigned int)((ctx->count[0]>>3)&0x3F);
    if((ctx->count[0]+=((uint32_t)len<<3))<((uint32_t)len<<3)) ctx->count[1]++;
    ctx->count[1]+=((uint32_t)len>>29);
    partLen=64-idx;
    if(len>=partLen){
        memcpy(&ctx->buffer[idx],input,partLen);
        md5Transform(ctx->state,ctx->buffer);
        for(i=partLen;i+63<len;i+=64) md5Transform(ctx->state,&input[i]);
        idx=0;
    } else i=0;
    memcpy(&ctx->buffer[idx],&input[i],len-i);
}

static void md5Final(unsigned char digest[16], MD5Context *ctx) {
    static unsigned char PADDING[64]={0x80};
    unsigned char bits[8]; unsigned int idx,padLen;
    md5Encode(bits,ctx->count,8);
    idx=(unsigned int)((ctx->count[0]>>3)&0x3f);
    padLen=(idx<56)?(56-idx):(120-idx);
    md5Update(ctx,PADDING,padLen);
    md5Update(ctx,bits,8);
    md5Encode(digest,ctx->state,16);
    memset(ctx,0,sizeof(*ctx));
}

std::string md5String(const std::string& str, bool upperCase=false) {
    MD5Context ctx; unsigned char digest[16];
    md5Init(&ctx);
    md5Update(&ctx,(const unsigned char*)str.c_str(),(unsigned int)str.size());
    md5Final(digest,&ctx);
    std::ostringstream oss;
    for(int i=0;i<16;i++)
        oss<<std::hex<<std::setfill('0')<<std::setw(2)<<(upperCase?std::uppercase:std::nouppercase)<<(int)digest[i];
    return oss.str();
}

/* ========== 字节/HEX转换工具 ========== */

std::string bytesToHex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for(auto b:data) oss<<std::hex<<std::uppercase<<std::setfill('0')<<std::setw(2)<<(int)b;
    return oss.str();
}

std::string stringToHex(const std::string& str) {
    std::ostringstream oss;
    for(unsigned char c:str) oss<<std::hex<<std::uppercase<<std::setfill('0')<<std::setw(2)<<(int)c;
    return oss.str();
}

int hexCharToInt(char c) {
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    return -1;
}

/* ========== 标准Base64解码(用于RSA公钥PEM解析) ========== */

static const char STD_B64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::vector<uint8_t> stdBase64Decode(const std::string& in) {
    unsigned char tbl[256]; memset(tbl,0xFF,256);
    for(int i=0;i<64;i++) tbl[(unsigned char)STD_B64[i]]=i;
    std::vector<uint8_t> out;
    int val=0,bits=0;
    for(char c:in){
        if(c=='='||c=='\n'||c=='\r'||c==' ') continue;
        if(tbl[(unsigned char)c]==0xFF) continue;
        val=(val<<6)|tbl[(unsigned char)c]; bits+=6;
        if(bits>=8){ bits-=8; out.push_back((uint8_t)((val>>bits)&0xFF)); }
    }
    return out;
}

} /* end anonymous namespace */

/* ========== 大数运算(纯C++, 无OpenSSL RSA实现) ========== */

#define BN_MAX 72

struct RSACrypto::BigNum {
    uint32_t w[BN_MAX];
    int len;
    
    BigNum() { memset(w,0,sizeof(w)); len=1; }
    
    void set(uint32_t v) { memset(w,0,sizeof(w)); w[0]=v; len=1; }
    void trim() { while(len>1&&w[len-1]==0) len--; }
    bool isZero() const { return len==1&&w[0]==0; }
    
    static BigNum fromBE(const unsigned char *b, int blen) {
        BigNum a; a.len=(blen+3)/4; if(a.len<1)a.len=1; if(a.len>BN_MAX)a.len=BN_MAX;
        for(int i=0;i<blen;i++){
            int wi=(blen-1-i)/4, bi=(blen-1-i)%4;
            if(wi<BN_MAX) a.w[wi]|=((uint32_t)b[i])<<(bi*8);
        }
        a.trim(); return a;
    }
    
    void toBE(unsigned char *b, int blen) const {
        memset(b,0,blen);
        for(int i=0;i<len&&i*4<blen;i++)
            for(int j=0;j<4&&i*4+j<blen;j++)
                b[blen-1-(i*4+j)]=(w[i]>>(j*8))&0xFF;
    }
    
    int cmp(const BigNum& o) const {
        if(len!=o.len) return len>o.len?1:-1;
        for(int i=len-1;i>=0;i--)
            if(w[i]!=o.w[i]) return w[i]>o.w[i]?1:-1;
        return 0;
    }
    
    static BigNum add(const BigNum& a, const BigNum& b) {
        BigNum c; int ml=a.len>b.len?a.len:b.len; uint64_t carry=0;
        for(int i=0;i<ml||(int)carry;i++){
            uint64_t s=carry;
            if(i<a.len)s+=a.w[i]; if(i<b.len)s+=b.w[i];
            c.w[i]=(uint32_t)(s&0xFFFFFFFF); carry=s>>32;
            c.len=i+1;
        }
        if(c.len>BN_MAX) c.len=BN_MAX;
        c.trim(); return c;
    }
    
    static BigNum sub(const BigNum& a, const BigNum& b) {
        BigNum c; int64_t borrow=0;
        for(int i=0;i<a.len;i++){
            int64_t d=(int64_t)a.w[i]-borrow;
            if(i<b.len) d-=b.w[i];
            if(d<0){d+=0x100000000LL;borrow=1;} else borrow=0;
            c.w[i]=(uint32_t)d;
        }
        c.len=a.len; c.trim(); return c;
    }
    
    static BigNum shl(const BigNum& a, int bits) {
        BigNum c; if(a.isZero()) return c;
        int ws=bits/32, bs=bits%32;
        if(bs==0){
            for(int i=0;i<a.len&&i+ws<BN_MAX;i++) c.w[i+ws]=a.w[i];
        } else {
            uint32_t carry=0;
            for(int i=0;i<a.len&&i+ws<BN_MAX;i++){
                uint64_t v=((uint64_t)a.w[i]<<bs)|carry;
                c.w[i+ws]=(uint32_t)(v&0xFFFFFFFF); carry=(uint32_t)(v>>32);
            }
            if(carry&&a.len+ws<BN_MAX) c.w[a.len+ws]=carry;
        }
        c.len=a.len+ws+1; if(c.len>BN_MAX) c.len=BN_MAX; c.trim(); return c;
    }
    
    static BigNum shr(const BigNum& a, int bits) {
        BigNum c; if(a.isZero()) return c;
        int ws=bits/32, bs=bits%32;
        if(ws>=a.len) return c;
        c.len=a.len-ws;
        if(bs==0){
            for(int i=0;i<c.len;i++) c.w[i]=a.w[i+ws];
        } else {
            for(int i=0;i<c.len;i++){
                c.w[i]=a.w[i+ws]>>bs;
                if(i+ws+1<a.len) c.w[i]|=a.w[i+ws+1]<<(32-bs);
            }
        }
        c.trim(); return c;
    }
    
    static BigNum mul(const BigNum& a, const BigNum& b) {
        BigNum r; r.len=a.len+b.len; if(r.len>BN_MAX) r.len=BN_MAX;
        for(int i=0;i<a.len;i++){
            uint64_t carry=0;
            for(int j=0;j<b.len&&i+j<BN_MAX;j++){
                uint64_t p=(uint64_t)a.w[i]*b.w[j]+r.w[i+j]+carry;
                r.w[i+j]=(uint32_t)(p&0xFFFFFFFF); carry=p>>32;
            }
            if(carry&&i+b.len<BN_MAX) r.w[i+b.len]+=(uint32_t)carry;
        }
        r.trim(); return r;
    }
    
    static BigNum mod(const BigNum& a, const BigNum& m) {
        BigNum r=a;
        if(m.isZero()||a.cmp(m)<0) return r;
        int shift=0;
        { BigNum t=m; while(t.cmp(r)<0){t=shl(t,1);shift++;}
          if(t.cmp(r)>0) shift--; }
        for(int i=shift;i>=0;i--){
            BigNum sh=shl(m,i);
            if(r.cmp(sh)>=0) r=sub(r,sh);
        }
        return r;
    }
    
    static BigNum modpow(const BigNum& base, const BigNum& exp, const BigNum& mod_) {
        BigNum res; res.set(1);
        BigNum b=mod(base,mod_); BigNum e=exp;
        while(!e.isZero()){
            if(e.w[0]&1) res=mod(mul(res,b),mod_);
            b=mod(mul(b,b),mod_);
            e=shr(e,1);
        }
        return res;
    }
};

/* ========== RSA密钥结构 ========== */

struct RSACrypto::RSAKey {
    RSACrypto::BigNum n, e;
    int keySize;
};

/* ========== RSACrypto 实现 ========== */

RSACrypto::RSACrypto(const std::string& publicKeyPem) : key_(nullptr), keySize_(0) {
    key_ = new RSAKey();
    parsePEM(publicKeyPem);
    if(t3_failed()){
        /* L2: 解析失败(原为构造函数抛出→由 initRSA 的 catch 吞掉)。
           置 0 值状态, 不留负数块长; 调用方检查错误槽后丢弃本对象。*/
        encryptBlockSize_ = 0;
        decryptBlockSize_ = 0;
        return;
    }
    encryptBlockSize_ = keySize_ - 11;
    decryptBlockSize_ = keySize_;
}

void RSACrypto::parsePEM(const std::string& pem) {
    t3_clear_error();   /* L2-FIX: 助手入口清槽, 只反映本次解析结果 */
    /* 提取Base64内容 (PEM定界符编译期加密, 二进制无明文指纹) */
    static const char* PEM_HDR = (const char*)AY_OBFUSCATE("-----BEGIN PUBLIC KEY-----");
    static const char* PEM_TLR = (const char*)AY_OBFUSCATE("-----END PUBLIC KEY-----");
    auto s = pem.find(PEM_HDR);
    auto e = pem.find(PEM_TLR);
    if(s==std::string::npos||e==std::string::npos){
        t3_raise("Invalid PEM format"); return;
    }
    s += strlen(PEM_HDR);
    std::string b64;
    for(size_t i=s;i<e;i++){
        char c=pem[i];
        if(c!='\n'&&c!='\r'&&c!=' '&&c!='\t') b64+=c;
    }
    
    /* Base64解码为DER */
    std::vector<uint8_t> der = stdBase64Decode(b64);
    if(der.empty()){ t3_raise("PEM base64 decode failed"); return; }
    
    /* ASN.1 DER 解析 */
    int off=0;
    auto readLen=[&]()->int{
        unsigned char f=der[off++]; int n,l=0;
        if(f<0x80) return f;
        n=f&0x7F;
        for(int i=0;i<n;i++){l=(l<<8)|der[off];off++;}
        return l;
    };
    
    /* 外层SEQUENCE */
    if(der[off]!=0x30){ t3_raise("DER: expected SEQUENCE"); return; }
    off++; readLen();
    /* AlgorithmIdentifier SEQUENCE */
    if(der[off]!=0x30){ t3_raise("DER: expected AlgorithmIdentifier"); return; }
    off++; int alen=readLen(); off+=alen;
    /* BIT STRING */
    if(der[off]!=0x03){ t3_raise("DER: expected BIT STRING"); return; }
    off++; readLen(); off++; /* skip unused bits byte */
    /* 内层SEQUENCE */
    if(der[off]!=0x30){ t3_raise("DER: expected inner SEQUENCE"); return; }
    off++; readLen();
    /* INTEGER n */
    if(der[off]!=0x02){ t3_raise("DER: expected INTEGER for n"); return; }
    off++; int nlen=readLen();
    if(der[off]==0x00){off++;nlen--;}
    key_->n = BigNum::fromBE(der.data()+off, nlen);
    key_->keySize = nlen;
    keySize_ = nlen;
    off+=nlen;
    /* INTEGER e */
    if(der[off]!=0x02){ t3_raise("DER: expected INTEGER for e"); return; }
    off++; int elen=readLen();
    key_->e = BigNum::fromBE(der.data()+off, elen);
}

AMICE_FLATTEN_H /*L2AMICE*/
std::vector<uint8_t> RSACrypto::encrypt(const std::string& data) const {
    std::vector<uint8_t> result;
    const uint8_t* msg = (const uint8_t*)data.c_str();
    int mlen = (int)data.size();
    int nb = (mlen + encryptBlockSize_ - 1) / encryptBlockSize_;
    if(nb<1) nb=1;
    
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(1,255);
    
    for(int i=0;i<nb;i++){
        int off=i*encryptBlockSize_;
        int cur=(off+encryptBlockSize_<=mlen)?encryptBlockSize_:(mlen-off);
        if(cur<0) cur=0;
        
        /* PKCS1 v1.5 填充 */
        std::vector<uint8_t> padded(keySize_,0);
        padded[0]=0x00; padded[1]=0x02;
        int pl=keySize_-cur-3;
        for(int j=0;j<pl;j++) padded[2+j]=(uint8_t)dist(rng);
        padded[2+pl]=0x00;
        if(cur>0) memcpy(padded.data()+3+pl, msg+off, cur);
        
        /* RSA: m^e mod n */
        BigNum m = BigNum::fromBE(padded.data(), keySize_);
        BigNum c = BigNum::modpow(m, key_->e, key_->n);
        std::vector<uint8_t> block(keySize_);
        c.toBE(block.data(), keySize_);
        result.insert(result.end(), block.begin(), block.end());
    }
    return result;
}

std::string RSACrypto::decrypt(const std::vector<uint8_t>& encryptedData) const {
    std::string result;
    int nb = (int)encryptedData.size() / decryptBlockSize_;
    
    for(int i=0;i<nb;i++){
        BigNum c = BigNum::fromBE(encryptedData.data()+i*decryptBlockSize_, decryptBlockSize_);
        BigNum m = BigNum::modpow(c, key_->e, key_->n);
        std::vector<uint8_t> blk(keySize_);
        m.toBE(blk.data(), keySize_);
        
        /* 去除PKCS1 v1.5 填充: 0x00 0x01 [0xFF...] 0x00 [data] */
        int padEnd=-1;
        for(int j=2;j<keySize_;j++){
            if(blk[j]==0x00){padEnd=j;break;}
        }
        if(padEnd!=-1){
            result.append((char*)blk.data()+padEnd+1, keySize_-padEnd-1);
        } else {
            result.append((char*)blk.data(), keySize_);
        }
    }
    return result;
}

std::string RSACrypto::encryptToHex(const std::string& data) const {
    return bytesToHex(encrypt(data));
}

std::string RSACrypto::decryptFromBase64(const std::string& base64Str) const {
    std::vector<uint8_t> enc = stdBase64Decode(base64Str);
    return decrypt(enc);
}

/* ========== CustomBase64 实现 ========== */

const std::string CustomBase64::STANDARD_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

CustomBase64::CustomBase64(const std::string& customCharset) : customCharset_(customCharset) {
    t3_clear_error();   /* L2-FIX: 构造函数入口清槽, 只反映本次构造结果 */
    if(customCharset.size()!=64){
        /* L2: 原 throw std::invalid_argument —— 改为记录错误 + 安全默认状态:
           回退到标准字符集, 保证 customCharset_[0..63] 始终可索引(不留越界读)。
           错误文案逐字保留; 调用方(init)检查错误槽后返回 false。*/
        t3_raise("自定义字符集必须是64位字符");
        customCharset_ = STANDARD_CHARSET;
    }
}

std::string CustomBase64::encode(const std::string& data) const {
    const unsigned char* d = (const unsigned char*)data.c_str();
    int dlen = (int)data.size();
    std::string out;
    for(int i=0;i<dlen;i+=3){
        int val=d[i]<<16;
        if(i+1<dlen) val|=d[i+1]<<8;
        if(i+2<dlen) val|=d[i+2];
        out+=STANDARD_CHARSET[(val>>18)&0x3F];
        out+=STANDARD_CHARSET[(val>>12)&0x3F];
        out+=(i+1<dlen)?STANDARD_CHARSET[(val>>6)&0x3F]:'=';
        out+=(i+2<dlen)?STANDARD_CHARSET[val&0x3F]:'=';
    }
    /* 转换为自定义字符集 */
    for(auto& c:out){
        if(c!='='){
            auto pos=STANDARD_CHARSET.find(c);
            if(pos!=std::string::npos) c=customCharset_[pos];
        }
    }
    return out;
}

std::string CustomBase64::decode(const std::string& data) const {
    /* 先转换回标准字符集 */
    std::string std64;
    for(char c:data){
        if(c=='='){std64+='=';continue;}
        auto pos=customCharset_.find(c);
        if(pos!=std::string::npos) std64+=STANDARD_CHARSET[pos];
        else std64+=c;
    }
    /* 标准Base64解码 */
    unsigned char tbl[256]; memset(tbl,0xFF,256);
    for(int i=0;i<64;i++) tbl[(unsigned char)STANDARD_CHARSET[i]]=i;
    std::string out;
    int len=(int)std64.size();
    for(int i=0;i<len;i+=4){
        int val=(tbl[(unsigned char)std64[i]]<<18)|
                (tbl[(unsigned char)std64[i+1]]<<12)|
                (tbl[(unsigned char)std64[i+2]]<<6)|
                 tbl[(unsigned char)std64[i+3]];
        out+=(char)((val>>16)&0xFF);
        if(std64[i+2]!='=') out+=(char)((val>>8)&0xFF);
        if(std64[i+3]!='=') out+=(char)(val&0xFF);
    }
    return out;
}

std::string CustomBase64::encodeToHex(const std::string& data) const {
    return stringToHex(encode(data));
}

/* ========== JSON解析辅助 ========== */

namespace {

int unicodeToUtf8(unsigned int cp, unsigned char *utf8) {
    if(cp<=0x7F){utf8[0]=(unsigned char)cp;return 1;}
    else if(cp<=0x7FF){utf8[0]=(unsigned char)(0xC0|(cp>>6));utf8[1]=(unsigned char)(0x80|(cp&0x3F));return 2;}
    else if(cp<=0xFFFF){utf8[0]=(unsigned char)(0xE0|(cp>>12));utf8[1]=(unsigned char)(0x80|((cp>>6)&0x3F));utf8[2]=(unsigned char)(0x80|(cp&0x3F));return 3;}
    else if(cp<=0x10FFFF){utf8[0]=(unsigned char)(0xF0|(cp>>18));utf8[1]=(unsigned char)(0x80|((cp>>12)&0x3F));utf8[2]=(unsigned char)(0x80|((cp>>6)&0x3F));utf8[3]=(unsigned char)(0x80|(cp&0x3F));return 4;}
    return 0;
}

std::string decodeJsonString(const std::string& in) {
    std::string out; size_t i=0;
    while(i<in.size()){
        if(in[i]=='\\'&&i+1<in.size()){
            i++;
            switch(in[i]){
                case '"': case '\\': case '/': out+=in[i]; break;
                case 'b': out+='\b'; break; case 'f': out+='\f'; break;
                case 'n': out+='\n'; break; case 'r': out+='\r'; break;
                case 't': out+='\t'; break;
                case 'u': {
                    if(i+4<in.size()){
                        unsigned int cp=0;
                        for(int j=0;j<4;j++){int v=hexCharToInt(in[i+1+j]);if(v<0)break;cp=(cp<<4)|v;}
                        unsigned char u[4]; int ul=unicodeToUtf8(cp,u);
                        for(int j=0;j<ul;j++) out+=(char)u[j];
                        i+=4;
                    }
                    break;
                }
                default: out+=in[i]; break;
            }
            i++;
        } else { out+=in[i]; i++; }
    }
    return out;
}

AMICE_FLATTEN_H /*L2AMICE*/
bool jsonGetString(const std::string& json, const std::string& key, std::string& value) {
    std::string sk="\""+key+"\"";
    auto pos=json.find(sk);
    if(pos==std::string::npos) return false;
    pos=json.find(':',pos); if(pos==std::string::npos) return false;
    pos++; while(pos<json.size()&&(json[pos]==' '||json[pos]=='\t')) pos++;
    if(pos>=json.size()) return false;
    if(json[pos]=='"') {
        pos++;
        std::string raw;
        while(pos<json.size()&&json[pos]!='"'){
            if(json[pos]=='\\'&&pos+1<json.size()){raw+=json[pos];raw+=json[pos+1];pos+=2;}
            else {raw+=json[pos];pos++;}
        }
        value=decodeJsonString(raw);
        return true;
    }
    // 处理非字符串值（数字、布尔、null）
    if(json.substr(pos,4)=="null") { value=""; return true; }
    std::string raw;
    while(pos<json.size()&&json[pos]!=','&&json[pos]!='}'&&json[pos]!=']'&&json[pos]!='\n') {
        raw+=json[pos]; pos++;
    }
    // 去除尾部空白
    while(!raw.empty()&&(raw.back()==' '||raw.back()=='\t'||raw.back()=='\r')) raw.pop_back();
    if(raw.empty()) return false;
    value=raw;
    return true;
}

bool jsonGetInt(const std::string& json, const std::string& key, int& value) {
    std::string sk="\""+key+"\"";
    auto pos=json.find(sk);
    if(pos==std::string::npos) return false;
    pos=json.find(':',pos); if(pos==std::string::npos) return false;
    pos++; while(pos<json.size()&&(json[pos]==' '||json[pos]=='\t')) pos++;
    value=atoi(json.c_str()+pos);
    return true;
}

} /* end anonymous namespace */

/* ========== HTTP客户端实现 ========== */

namespace {

struct URLInfo {
    std::string protocol, host, path;
    int port;
};

bool parseUrl(const std::string& url, URLInfo& info) {
    if(url.substr(0,8)=="https://"){info.protocol="https";info.port=443;}
    else if(url.substr(0,7)=="http://"){info.protocol="http";info.port=80;}
    else return false;
    size_t start=(info.protocol=="https")?8:7;
    auto pathPos=url.find('/',start);
    if(pathPos!=std::string::npos){
        std::string hostPart=url.substr(start,pathPos-start);
        auto colonPos=hostPart.find(':');
        if(colonPos!=std::string::npos){
            info.host=hostPart.substr(0,colonPos);
            info.port=atoi(hostPart.substr(colonPos+1).c_str());
        } else info.host=hostPart;
        info.path=url.substr(pathPos);
    } else {
        info.host=url.substr(start);
        info.path="/";
    }
    return true;
}

bool connectWithTimeout(int sock, const struct sockaddr *address, int addressLength, int seconds) {
    #ifdef _WIN32
    u_long nonBlocking=1;
    ioctlsocket(sock,FIONBIO,&nonBlocking);
    int result=connect(sock,address,addressLength);
    if(result==SOCKET_ERROR&&WSAGetLastError()!=WSAEWOULDBLOCK){ nonBlocking=0; ioctlsocket(sock,FIONBIO,&nonBlocking); return false; }
    fd_set writeSet; FD_ZERO(&writeSet); FD_SET(sock,&writeSet);
    timeval timeout={seconds,0};
    result=select(0,nullptr,&writeSet,nullptr,&timeout);
    int socketError=0; int errorLength=sizeof(socketError);
    if(result>0) getsockopt(sock,SOL_SOCKET,SO_ERROR,(char*)&socketError,&errorLength);
    nonBlocking=0; ioctlsocket(sock,FIONBIO,&nonBlocking);
    return result>0&&socketError==0;
    #else
    int flags=fcntl(sock,F_GETFL,0);
    if(flags<0) return false;
    if(fcntl(sock,F_SETFL,flags|O_NONBLOCK)<0) return false;
    int result=connect(sock,address,addressLength);
    if(result<0&&errno!=EINPROGRESS){ fcntl(sock,F_SETFL,flags); return false; }
    fd_set writeSet; FD_ZERO(&writeSet); FD_SET(sock,&writeSet);
    timeval timeout={seconds,0};
    result=select(sock+1,nullptr,&writeSet,nullptr,&timeout);
    int socketError=0; socklen_t errorLength=sizeof(socketError);
    if(result>0) getsockopt(sock,SOL_SOCKET,SO_ERROR,&socketError,&errorLength);
    fcntl(sock,F_SETFL,flags);
    return result>0&&socketError==0;
    #endif
}

std::string httpPostRaw(const std::string& url, const std::string& postData) {
    URLInfo info;
    if(!parseUrl(url,info)) return "";
    
    /* HTTPS降级为HTTP（与C版本一致） */
    if(info.protocol=="https") info.port=80;
    
    #ifdef _WIN32
    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2,2),&wsa)!=0) return "";
    #endif
    
    struct hostent *host=gethostbyname(info.host.c_str());
    if(!host){
        #ifdef _WIN32
        WSACleanup();
        #endif
        return "";
    }
    
    int sock=socket(AF_INET,SOCK_STREAM,0);
    if(sock<0){
        #ifdef _WIN32
        WSACleanup();
        #endif
        return "";
    }
    
    struct sockaddr_in server;
    server.sin_family=AF_INET;
    server.sin_port=htons(info.port);
    memcpy(&server.sin_addr,host->h_addr,host->h_length);
    
    if(!connectWithTimeout(sock,(struct sockaddr*)&server,sizeof(server),3)){
        #ifdef _WIN32
        closesocket(sock); WSACleanup();
        #else
        close(sock);
        #endif
        return "";
    }

    #ifdef _WIN32
    DWORD socketTimeout=7000;
    setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(const char*)&socketTimeout,sizeof(socketTimeout));
    setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,(const char*)&socketTimeout,sizeof(socketTimeout));
    #else
    timeval socketTimeout={7,0};
    setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&socketTimeout,sizeof(socketTimeout));
    setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,&socketTimeout,sizeof(socketTimeout));
    #endif
    
    std::ostringstream req;
    req<<"POST "<<info.path<<" HTTP/1.1\r\n"
       <<"Host: "<<info.host<<"\r\n"
       <<"Content-Type: application/x-www-form-urlencoded\r\n"
       <<"Content-Length: "<<postData.size()<<"\r\n"
       <<"Connection: close\r\n"
       <<"\r\n"
       <<postData;
    std::string reqStr=req.str();
    
    if(send(sock,reqStr.c_str(),(int)reqStr.size(),0)<0){
        #ifdef _WIN32
        closesocket(sock); WSACleanup();
        #else
        close(sock);
        #endif
        return "";
    }
    
    std::string response;
    char buf[4096];
    int n;
    while((n=recv(sock,buf,sizeof(buf)-1,0))>0){
        buf[n]='\0'; response+=buf;
    }
    
    #ifdef _WIN32
    closesocket(sock); WSACleanup();
    #else
    close(sock);
    #endif
    
    /* 408/5xx 是可切换线路的网络故障 */
    auto lineEnd=response.find("\r\n");
    int status=0;
    if(lineEnd!=std::string::npos){
        std::istringstream statusLine(response.substr(0,lineEnd));
        std::string version; statusLine>>version>>status;
    }
    if(status==408||status>=500) return "";

    /* 提取HTTP body */
    auto bodyPos=response.find("\r\n\r\n");
    if(bodyPos!=std::string::npos)
        return response.substr(bodyPos+4);
    return response;
}

} /* end anonymous namespace */

/* ========== 机器码获取 ========== */

AMICE_FLATTEN_H /*L2AMICE*/
std::string getMachineCode() {
    std::string macStr;
    
    #ifdef _WIN32
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufLen=sizeof(adapterInfo);
    if(GetAdaptersInfo(adapterInfo,&bufLen)==ERROR_SUCCESS){
        PIP_ADAPTER_INFO adapter=adapterInfo;
        if(adapter){
            char buf[32];
            snprintf(buf,sizeof(buf),"%02X:%02X:%02X:%02X:%02X:%02X",
                adapter->Address[0],adapter->Address[1],adapter->Address[2],
                adapter->Address[3],adapter->Address[4],adapter->Address[5]);
            macStr=buf;
        }
    }
    #elif defined(__APPLE__)
    int mib[6]; size_t len; char *buf; unsigned char *ptr;
    struct if_msghdr *ifm; struct sockaddr_dl *sdl;
    mib[0]=CTL_NET; mib[1]=AF_ROUTE; mib[2]=0; mib[3]=AF_LINK; mib[4]=NET_RT_IFLIST;
    if((mib[5]=if_nametoindex("en0"))!=0){
        if(sysctl(mib,6,NULL,&len,NULL,0)==0){
            buf=(char*)malloc(len);
            if(buf&&sysctl(mib,6,buf,&len,NULL,0)==0){
                ifm=(struct if_msghdr*)buf;
                sdl=(struct sockaddr_dl*)(ifm+1);
                ptr=(unsigned char*)LLADDR(sdl);
                char tmp[32];
                snprintf(tmp,sizeof(tmp),"%02X:%02X:%02X:%02X:%02X:%02X",
                    ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
                macStr=tmp;
            }
            free(buf);
        }
    }
    #else
    struct ifreq ifr; int sock=socket(AF_INET,SOCK_DGRAM,0);
    if(sock>=0){
        const char* ifaces[]={"wlan0","swlan0","eth0","wlan1","ens33","enp0s3",NULL};/*Android: wlan0优先*/
        for(int i=0;ifaces[i];i++){
            strncpy(ifr.ifr_name,ifaces[i],IFNAMSIZ-1);
            if(ioctl(sock,SIOCGIFHWADDR,&ifr)==0){
                unsigned char *mac=(unsigned char*)ifr.ifr_hwaddr.sa_data;
                char tmp[32];
                snprintf(tmp,sizeof(tmp),"%02X:%02X:%02X:%02X:%02X:%02X",
                    mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
                macStr=tmp;
                break;
            }
        }
        close(sock);
    }
    #endif
    
    if(macStr.empty()) macStr="00:00:00:00:00:00";
    return md5String(macStr, true);
}

/* ========== T3Verify 实现 ========== */

T3Verify::T3Verify()
    : serverUrls_({"https://w.t3yanzheng.com/", "https://w2.t3yanzheng.com/", "https://w3.t3yanzheng.com/",
                   "https://w4.t3yanzheng.com/", "https://w5.t3yanzheng.com/", "https://w.t3data.net/"}),
      encodeType_(0), initialized_(false), encoder_(nullptr), rsaCrypto_(nullptr) {
    std::random_device rd;
    std::mt19937 generator(rd());
    std::shuffle(serverUrls_.begin(), serverUrls_.end(), generator);
    serverUrl_=serverUrls_.front();
}

T3Verify::~T3Verify() {
    delete encoder_;
    delete rsaCrypto_;
}

bool T3Verify::init(const std::string& loginCode, const std::string& noticeCode,
                    const std::string& versionCode, const std::string& heartbeatCode,
                    const std::string& appkey, const std::string& base64Charset) {
    if(base64Charset.size()!=64) return false;
    loginCode_=loginCode; noticeCode_=noticeCode;
    versionCode_=versionCode; heartbeatCode_=heartbeatCode;
    appkey_=appkey; encodeType_=0;
    delete encoder_; encoder_=new CustomBase64(base64Charset);
    if(t3_failed()){
        /* L2: 原 catch(...) 直接 return false (丢弃 e.what())。
           取走错误槽, 避免残留错误污染后续 t3_failed() 检查; 语义等价。*/
        delete encoder_; encoder_=nullptr;
        t3_take_error();
        return false;
    }
    initialized_=true;
    return true;
}

AMICE_FLATTEN_H /*L2AMICE*/
bool T3Verify::initRSA(const std::string& loginCode, const std::string& noticeCode,
                       const std::string& versionCode, const std::string& heartbeatCode,
                       const std::string& appkey, const std::string& rsaPublicKey) {
    loginCode_=loginCode; noticeCode_=noticeCode;
    versionCode_=versionCode; heartbeatCode_=heartbeatCode;
    appkey_=appkey; encodeType_=1;
    delete rsaCrypto_; rsaCrypto_=new RSACrypto(rsaPublicKey);
    if(t3_failed()){
        /* L2: 原 catch(...) 直接 return false (丢弃 e.what())。
           取走错误槽; 并把半成品对象置空(原实现会留下悬垂指针), 语义等价。*/
        delete rsaCrypto_; rsaCrypto_=nullptr;
        t3_take_error();
        return false;
    }
    initialized_=true;
    return true;
}

void T3Verify::checkInit() const {
    t3_clear_error();   /* L2-FIX(核心): 清掉【前面请求】残留的错误。
                           login/simpleRequest 等的 checkInit()+t3_failed() 检查点
                           现在只反映 initialized_ 本身, 不再被 getNotice/
                           getLatestVersion 的局部失败污染。 */
    if(!initialized_){ t3_raise("未初始化，请先调用 init() 或 initRSA()"); return; }
}

std::string T3Verify::buildUrl(const std::string& code) const {
    if(!serverUrl_.empty()&&serverUrl_.back()=='/') return serverUrl_+code;
    return serverUrl_+"/"+code;
}

std::string T3Verify::encodeValue(const std::string& value) const {
    if(encodeType_==0) return encoder_->encodeToHex(value);
    else return rsaCrypto_->encryptToHex(value);
}

AMICE_FLATTEN_H /*L2AMICE*/
std::string T3Verify::decodeResponse(const std::string& responseText) const {
    /* 清理响应 */
    std::string data=responseText;
    auto nl=data.find('\n');
    if(nl!=std::string::npos) data=data.substr(nl+1);
    /* 去除\r\n */
    std::string clean;
    for(char c:data) if(c!='\r'&&c!='\n') clean+=c;
    /* 去除末尾的0 */
    if(!clean.empty()&&clean.back()=='0') clean.pop_back();
    
    if(encodeType_==0) return encoder_->decode(clean);
    else return rsaCrypto_->decryptFromBase64(clean);
}

AMICE_FLATTEN_H /*L2AMICE*/
std::pair<std::vector<std::pair<std::string,std::string>>,std::string>
T3Verify::encodeParams(const std::vector<std::pair<std::string,std::string>>& params) const {
    /* 1. 每个值只编码一次，保持原始顺序 */
    std::vector<std::pair<std::string,std::string>> encoded;
    for(auto& p:params) encoded.push_back({p.first, encodeValue(p.second)});
    
    /* 2. 用已编码的值构建签名字符串 */
    std::string sStr;
    for(size_t i=0;i<encoded.size();i++){
        if(i>0) sStr+="&";
        sStr+=encoded[i].first+"="+encoded[i].second;
    }
    sStr+="&"+appkey_;
    
    /* 3. MD5签名再编码，追加到参数末尾 */
    std::string sValue=md5String(sStr);
    encoded.push_back({"s", encodeValue(sValue)});
    
    return {encoded, sStr};
}

std::string T3Verify::httpPost(const std::string& url,
                               const std::vector<std::pair<std::string,std::string>>& data) {
    t3_clear_error();   /* L2-FIX: 助手入口清槽; 失败只由下方"所有服务器都失败"处 raise 一次 */
    std::string postData;
    for(auto& p:data){
        if(!postData.empty()) postData+="&";
        postData+=p.first+"="+p.second;
    }
    URLInfo original;
    if(!parseUrl(url,original)){ t3_raise("无效的URL"); return std::string(); }
    std::vector<std::string> candidates={serverUrl_};
    for(const auto& base:serverUrls_) if(base!=serverUrl_) candidates.push_back(base);
    for(const auto& base:candidates){
        std::string target=base;
        if(!target.empty()&&target.back()=='/'&&!original.path.empty()&&original.path.front()=='/') target.pop_back();
        target+=original.path;
        std::string response=httpPostRaw(target,postData);
        if(!response.empty()){ serverUrl_=base; return response; }
    }
    t3_raise("无法连接到所有T3网络验证服务器，可能是因为您的网络问题或T3网络验证服务器被攻击造成的，建议检查网络或稍后重试");
    return std::string();
}

AMICE_FLATTEN_H /*L2AMICE*/
T3LoginResult T3Verify::login(const std::string& kami, const std::string& imei) {
    T3LoginResult result;
    checkInit();
    if(t3_failed()){ result.error=t3_take_error(); return result; }
    std::string url=buildUrl(loginCode_);
    time_t now=time(NULL);
    std::string tStr=std::to_string((long)now);

    std::vector<std::pair<std::string,std::string>> params={
        {"kami",kami},{"imei",imei},{"t",tStr}
    };
    auto [encoded, sOriginal]=encodeParams(params);

    std::string response=httpPost(url,encoded);
    if(response.empty()){ result.error=t3_take_error_or("HTTP请求失败"); return result; }

    std::string decoded=decodeResponse(response);
    if(t3_failed()){ result.error=t3_take_error_or("响应解码失败"); return result; }

    int code=0;
    if(!jsonGetInt(decoded,"code",code)){result.error="响应不是有效的JSON格式";return result;}
    if(code!=200){
        std::string msg; jsonGetString(decoded,"msg",msg);
        result.error=msg.empty()?"未知错误":msg; return result;
    }

    std::string kamiId,endTime,token,statecode;
    int responseTime=0;
    if(!jsonGetString(decoded,"id",kamiId)||!jsonGetString(decoded,"end_time",endTime)||
       !jsonGetString(decoded,"token",token)||!jsonGetString(decoded,"statecode",statecode)||
       !jsonGetInt(decoded,"time",responseTime)){
        result.error="响应数据缺少必要字段"; return result;
    }

    int timeDiff=abs((int)now-responseTime);
    if(timeDiff>5){
        result.error="时间戳校验失败，相差"+std::to_string(timeDiff)+"秒"; return result;
    }

    /* 生成预期token */
    struct tm *tmInfo=localtime(&now);
    char dateStr[16];
    strftime(dateStr,sizeof(dateStr),"%Y%m%d%H%M",tmInfo);
    std::string tokenSrc=kamiId+appkey_+sOriginal+endTime+dateStr;
    std::string expectedToken=md5String(tokenSrc);

    /* token比较(忽略大小写) */
    std::string tLower=token, eLower=expectedToken;
    std::transform(tLower.begin(),tLower.end(),tLower.begin(),::tolower);
    std::transform(eLower.begin(),eLower.end(),eLower.begin(),::tolower);
    if(tLower!=eLower){result.error="token校验失败";return result;}

    statecode_=statecode; endTime_=endTime;
    result.success=true; result.id=kamiId;
    result.end_time=endTime; result.statecode=statecode;
    jsonGetString(decoded, "recharge", result.recharge);
    jsonGetString(decoded, "use_time", result.use_time);
    jsonGetString(decoded, "available", result.available);
    jsonGetString(decoded, "imei", result.imei);
    jsonGetString(decoded, "change", result.change);
    jsonGetString(decoded, "core", result.core);
    jsonGetString(decoded, "amount", result.amount);
    return result;
}




AMICE_FLATTEN_H /*L2AMICE*/
T3Result T3Verify::heartbeat(const std::string& kami, const std::string& statecode) {
    return simpleRequest(heartbeatCode_, "单码心跳", {{"kami",kami},{"statecode",statecode}});
}

/* ========== 设置新增调用码 ========== */

void T3Verify::setCode(const std::string& field, const std::string& code) {
    std::map<std::string, std::string*> codeMap = {
        {"query", &queryCode_}, {"register", &registerCode_},
        {"user_login", &userLoginCode_}, {"user_heartbeat", &userHeartbeatCode_},
        {"qq_login", &qqLoginCode_}, {"bind_qq", &bindQQCode_},
        {"change_password", &changePasswordCode_}, {"user_cancel", &userCancelCode_},
        {"recharge", &rechargeCode_},
        {"kami_recharge", &kamiRechargeCode_}, {"unbind", &unbindCode_},
        {"ip_unbind", &ipUnbindCode_}, {"disable", &disableCode_},
        {"check_update", &checkUpdateCode_}, {"get_variable", &getVariableCode_},
        {"modify_variable", &modifyVariableCode_}, {"modify_core", &modifyCoreCode_},
        {"get_kami_core", &getKamiCoreCode_}, {"get_user_core", &getUserCoreCode_},
        {"online_kami", &onlineKamiCode_}, {"online_user", &onlineUserCode_},
        {"cloud_doc", &cloudDocCode_}, {"app_sign", &appSignCode_},
        {"qq_get_variable", &getVariableByQqCode_}, {"qq_heartbeat", &qqHeartbeatCode_},
        {"qq_get_core", &getUserCoreByQqCode_}, {"qq_modify_core", &modifyUserCoreByQqCode_},
        {"qq_unbind", &unbindQqCode_}, {"heartbeat_any", &heartbeatAnyCode_},
    };
    auto it = codeMap.find(field);
    if (it != codeMap.end()) *(it->second) = code;
}

/* ========== 通用简单请求 ========== */

AMICE_FLATTEN_H /*L2AMICE*/
T3Result T3Verify::simpleRequest(const std::string& code, const std::string& codeName,
                                  const std::vector<std::pair<std::string, std::string>>& params) {
    T3Result result;
    checkInit();
    if (t3_failed()) { result.error = t3_take_error(); return result; }
    if (code.empty()) { result.error = "未设置 " + codeName + " 调用码"; return result; }
    auto allParams = params;
    allParams.push_back({"t", std::to_string((long)time(NULL))});
    auto [encoded, _] = encodeParams(allParams);
    std::string response = httpPost(buildUrl(code), encoded);
    if (response.empty()) { result.error = t3_take_error_or("HTTP请求失败"); return result; }
    std::string decoded = decodeResponse(response);
    if (t3_failed()) { result.error = t3_take_error_or("响应解码失败"); return result; }
    int c = 0;
    if (!jsonGetInt(decoded, "code", c)) { result.error = "响应不是有效的JSON格式"; return result; }
    if (c != 200) { std::string msg; jsonGetString(decoded, "msg", msg); result.error = msg.empty() ? "未知错误" : msg; return result; }
    std::string msg; jsonGetString(decoded, "msg", msg);
    result.success = true; result.msg = msg;
    return result;
}

/* ========== 查询卡密 ========== */

T3QueryResult T3Verify::queryKami(const std::string& kami) {
    T3QueryResult result;
    checkInit();
    if (t3_failed()) { result.error = t3_take_error(); return result; }
    if (queryCode_.empty()) { result.error = "未设置查询卡密调用码"; return result; }
    auto [encoded, _] = encodeParams({{"kami", kami}, {"t", std::to_string((long)time(NULL))}});
    std::string response = httpPost(buildUrl(queryCode_), encoded);
    if (response.empty()) { result.error = t3_take_error_or("HTTP请求失败"); return result; }
    std::string decoded = decodeResponse(response);
    if (t3_failed()) { result.error = t3_take_error_or("响应解码失败"); return result; }
    int c = 0;
    if (!jsonGetInt(decoded, "code", c)) { result.error = "响应不是有效的JSON格式"; return result; }
    if (c != 200) { std::string msg; jsonGetString(decoded, "msg", msg); result.error = msg.empty() ? "未知错误" : msg; return result; }
    result.success = true;
    jsonGetString(decoded, "state", result.state);
    jsonGetString(decoded, "use", result.use);
    jsonGetString(decoded, "id", result.id);
    jsonGetString(decoded, "use_time", result.use_time);
    jsonGetString(decoded, "end_time", result.end_time);
    jsonGetString(decoded, "line_time", result.line_time);
    jsonGetString(decoded, "line", result.line);
    jsonGetString(decoded, "amount", result.amount);
    jsonGetString(decoded, "available", result.available);
    return result;
}

/* ========== 数据与内容 ========== */

T3NoticeResult T3Verify::getNotice() {
    T3NoticeResult result;
    auto r = simpleRequest(noticeCode_, "公告", {});
    if (r.success) { result.success = true; result.notice = r.msg; }
    else result.error = r.error;
    return result;
}

T3VersionResult T3Verify::getLatestVersion() {
    T3VersionResult result;
    auto r = simpleRequest(versionCode_, "版本号", {});
    if (r.success) { result.success = true; result.version = r.msg; }
    else result.error = r.error;
    return result;
}

T3UpdateResult T3Verify::checkUpdate(const std::string& ver) {
    T3UpdateResult result;
    checkInit();
    if (t3_failed()) { result.error = t3_take_error(); return result; }
    if (checkUpdateCode_.empty()) { result.error = "未设置检查更新调用码"; return result; }
    auto [encoded, _] = encodeParams({{"ver", ver}, {"t", std::to_string((long)time(NULL))}});
    std::string response = httpPost(buildUrl(checkUpdateCode_), encoded);
    if (response.empty()) { result.error = t3_take_error_or("HTTP请求失败"); return result; }
    std::string decoded = decodeResponse(response);
    if (t3_failed()) { result.error = t3_take_error_or("响应解码失败"); return result; }
    int c = 0;
    if (!jsonGetInt(decoded, "code", c)) { result.error = "响应不是有效的JSON格式"; return result; }
    if (c == 200) {
        result.success = true; result.hasUpdate = true;
        jsonGetString(decoded, "ver", result.ver);
        jsonGetString(decoded, "version", result.version);
        jsonGetString(decoded, "uplog", result.uplog);
        jsonGetString(decoded, "upurl", result.upurl);
    } else if (c == 201) {
        result.success = true; result.hasUpdate = false;
        jsonGetString(decoded, "msg", result.msg);
    } else {
        std::string msg; jsonGetString(decoded, "msg", msg);
        result.error = msg.empty() ? "未知错误" : msg;
    }
    return result;
}

T3CloudDocResult T3Verify::getCloudDoc(const std::string& token) {
    T3CloudDocResult result;
    auto r = simpleRequest(cloudDocCode_, "云文档", {{"token", token}});
    if (r.success) { result.success = true; result.content = r.msg; }
    else result.error = r.error;
    return result;
}

T3AppSignResult T3Verify::appSign(const std::string& autograph) {
    T3AppSignResult result;
    checkInit();
    if (t3_failed()) { result.error = t3_take_error(); return result; }
    if (appSignCode_.empty()) { result.error = "未设置应用签名调用码"; return result; }
    auto [encoded, _] = encodeParams({{"autograph", autograph}, {"t", std::to_string((long)time(NULL))}});
    std::string response = httpPost(buildUrl(appSignCode_), encoded);
    if (response.empty()) { result.error = t3_take_error_or("HTTP请求失败"); return result; }
    std::string decoded = decodeResponse(response);
    if (t3_failed()) { result.error = t3_take_error_or("响应解码失败"); return result; }
    int c = 0;
    if (!jsonGetInt(decoded, "code", c)) { result.error = "响应不是有效的JSON格式"; return result; }
    if (c != 200) { std::string msg; jsonGetString(decoded, "msg", msg); result.error = msg.empty() ? "未知错误" : msg; return result; }
    result.success = true;
    jsonGetString(decoded, "msg", result.msg);
    jsonGetString(decoded, "autograph", result.autograph);
    int t = 0; jsonGetInt(decoded, "time", t); result.time = t;
    return result;
}

/* ========== 用户体系 ========== */

T3Result T3Verify::userRegister(const std::string& user, const std::string& pass, const std::string& email) {
    std::vector<std::pair<std::string, std::string>> params = {{"user", user}, {"pass", pass}};
    if (!email.empty()) params.push_back({"email", email});
    return simpleRequest(registerCode_, "用户注册", params);
}

T3LoginResult T3Verify::userLogin(const std::string& user, const std::string& pass, const std::string& imei) {
    T3LoginResult result;
    checkInit();
    if (t3_failed()) { result.error = t3_take_error(); return result; }
    if (userLoginCode_.empty()) { result.error = "未设置用户登录调用码"; return result; }
    auto [encoded, _] = encodeParams({{"user", user}, {"pass", pass}, {"imei", imei}, {"t", std::to_string((long)time(NULL))}});
    std::string response = httpPost(buildUrl(userLoginCode_), encoded);
    if (response.empty()) { result.error = t3_take_error_or("HTTP请求失败"); return result; }
    std::string decoded = decodeResponse(response);
    if (t3_failed()) { result.error = t3_take_error_or("响应解码失败"); return result; }
    int c = 0;
    if (!jsonGetInt(decoded, "code", c)) { result.error = "响应不是有效的JSON格式"; return result; }
    if (c != 200) { std::string msg; jsonGetString(decoded, "msg", msg); result.error = msg.empty() ? "未知错误" : msg; return result; }
    result.success = true;
    jsonGetString(decoded, "id", result.id);
    jsonGetString(decoded, "end_time", result.end_time);
    jsonGetString(decoded, "statecode", result.statecode);
    jsonGetString(decoded, "recharge", result.recharge);
    jsonGetString(decoded, "use_time", result.use_time);
    jsonGetString(decoded, "available", result.available);
    jsonGetString(decoded, "imei", result.imei);
    jsonGetString(decoded, "change", result.change);
    jsonGetString(decoded, "core", result.core);
    statecode_ = result.statecode; endTime_ = result.end_time;
    return result;
}

T3Result T3Verify::userHeartbeat(const std::string& user, const std::string& pass, const std::string& statecode) {
    return simpleRequest(userHeartbeatCode_, "用户心跳", {{"user", user}, {"pass", pass}, {"statecode", statecode}});
}

T3LoginResult T3Verify::qqLogin(const std::string& openid, const std::string& accessToken) {
    T3LoginResult result;
    checkInit();
    if (t3_failed()) { result.error = t3_take_error(); return result; }
    if (qqLoginCode_.empty()) { result.error = "未设置QQ登录调用码"; return result; }
    auto [encoded, _] = encodeParams({{"openid", openid}, {"access_token", accessToken}, {"t", std::to_string((long)time(NULL))}});
    std::string response = httpPost(buildUrl(qqLoginCode_), encoded);
    if (response.empty()) { result.error = t3_take_error_or("HTTP请求失败"); return result; }
    std::string decoded = decodeResponse(response);
    if (t3_failed()) { result.error = t3_take_error_or("响应解码失败"); return result; }
    int c = 0;
    if (!jsonGetInt(decoded, "code", c)) { result.error = "响应不是有效的JSON格式"; return result; }
    if (c != 200) { std::string msg; jsonGetString(decoded, "msg", msg); result.error = msg.empty() ? "未知错误" : msg; return result; }
    result.success = true;
    jsonGetString(decoded, "id", result.id);
    jsonGetString(decoded, "end_time", result.end_time);
    jsonGetString(decoded, "statecode", result.statecode);
    jsonGetString(decoded, "recharge", result.recharge);
    jsonGetString(decoded, "use_time", result.use_time);
    jsonGetString(decoded, "available", result.available);
    jsonGetString(decoded, "imei", result.imei);
    jsonGetString(decoded, "change", result.change);
    jsonGetString(decoded, "core", result.core);
    statecode_ = result.statecode; endTime_ = result.end_time;
    return result;
}

T3Result T3Verify::bindQQ(const std::string& user, const std::string& pass, const std::string& openid, const std::string& accessToken) {
    return simpleRequest(bindQQCode_, "绑定QQ", {{"user", user}, {"pass", pass}, {"openid", openid}, {"access_token", accessToken}});
}

T3Result T3Verify::changePassword(const std::string& user, const std::string& oldpass, const std::string& newpass) {
    return simpleRequest(changePasswordCode_, "修改密码", {{"user", user}, {"oldpass", oldpass}, {"newpass", newpass}});
}

T3Result T3Verify::userCancel(const std::string& user, const std::string& pass) {
    return simpleRequest(userCancelCode_, "用户注销", {{"user", user}, {"pass", pass}});
}

T3Result T3Verify::recharge(const std::string& user, const std::string& card) {
    return simpleRequest(rechargeCode_, "用户充值", {{"user", user}, {"card", card}});
}

T3Result T3Verify::kamiRecharge(const std::string& targetKami, const std::string& sourceKami) {
    return simpleRequest(kamiRechargeCode_, "单码以卡充卡", {{"target_kami", targetKami}, {"source_kami", sourceKami}});
}

/* ========== 设备与安全 ========== */

T3Result T3Verify::unbindKami(const std::string& kami, const std::string& imei) {
    return simpleRequest(unbindCode_, "解绑设备", {{"kami", kami}, {"imei", imei}});
}

T3Result T3Verify::unbindUser(const std::string& user, const std::string& pass, const std::string& imei) {
    return simpleRequest(unbindCode_, "解绑设备", {{"user", user}, {"pass", pass}, {"imei", imei}});
}

T3Result T3Verify::ipUnbindKami(const std::string& kami) {
    return simpleRequest(ipUnbindCode_, "IP解绑", {{"kami", kami}});
}

T3Result T3Verify::ipUnbindUser(const std::string& user, const std::string& pass) {
    return simpleRequest(ipUnbindCode_, "IP解绑", {{"user", user}, {"pass", pass}});
}

T3Result T3Verify::disableKami(const std::string& kami) {
    return simpleRequest(disableCode_, "禁用", {{"kami", kami}});
}

T3Result T3Verify::disableUser(const std::string& user, const std::string& pass) {
    return simpleRequest(disableCode_, "禁用", {{"user", user}, {"pass", pass}});
}

/* ========== 远程变量 ========== */

T3VariableResult T3Verify::getVariableByKami(const std::string& kami, const std::string& valueid, const std::string& valuename) {
    T3VariableResult result;
    auto r = simpleRequest(getVariableCode_, "获取变量", {{"kami", kami}, {"valueid", valueid}, {"valuename", valuename}});
    if (r.success) { result.success = true; result.value = r.msg; }
    else result.error = r.error;
    return result;
}

T3VariableResult T3Verify::getVariableByUser(const std::string& user, const std::string& pass, const std::string& valueid, const std::string& valuename) {
    T3VariableResult result;
    auto r = simpleRequest(getVariableCode_, "获取变量", {{"user", user}, {"pass", pass}, {"valueid", valueid}, {"valuename", valuename}});
    if (r.success) { result.success = true; result.value = r.msg; }
    else result.error = r.error;
    return result;
}

T3Result T3Verify::modifyVariableByKami(const std::string& kami, const std::string& valueid, const std::string& valuecontent) {
    return simpleRequest(modifyVariableCode_, "修改变量", {{"kami", kami}, {"valueid", valueid}, {"valuecontent", valuecontent}});
}

T3Result T3Verify::modifyVariableByUser(const std::string& user, const std::string& pass, const std::string& valueid, const std::string& valuecontent) {
    return simpleRequest(modifyVariableCode_, "修改变量", {{"user", user}, {"pass", pass}, {"valueid", valueid}, {"valuecontent", valuecontent}});
}

/* ========== 核心数据 ========== */

T3Result T3Verify::modifyCoreByKami(const std::string& kami, const std::string& core) {
    return simpleRequest(modifyCoreCode_, "修改核心数据", {{"kami", kami}, {"core", core}});
}

T3Result T3Verify::modifyCoreByUser(const std::string& user, const std::string& pass, const std::string& core) {
    return simpleRequest(modifyCoreCode_, "修改核心数据", {{"user", user}, {"pass", pass}, {"core", core}});
}

T3CoreResult T3Verify::getCoreByKami(const std::string& kami) {
    T3CoreResult result;
    auto r = simpleRequest(getKamiCoreCode_, "获取卡密核心数据", {{"kami", kami}});
    if (r.success) { result.success = true; result.core = r.msg; }
    else result.error = r.error;
    return result;
}

T3CoreResult T3Verify::getCoreByUser(const std::string& user, const std::string& pass) {
    T3CoreResult result;
    auto r = simpleRequest(getUserCoreCode_, "获取用户核心数据", {{"user", user}, {"pass", pass}});
    if (r.success) { result.success = true; result.core = r.msg; }
    else result.error = r.error;
    return result;
}

/* ========== 在线数量 ========== */

T3OnlineResult T3Verify::getOnlineKamiCount() {
    T3OnlineResult result;
    auto r = simpleRequest(onlineKamiCode_, "获取在线卡密数量", {});
    if (r.success) { result.success = true; result.count = atoi(r.msg.c_str()); }
    else result.error = r.error;
    return result;
}

T3OnlineResult T3Verify::getOnlineUserCount() {
    T3OnlineResult result;
    auto r = simpleRequest(onlineUserCode_, "获取在线用户数量", {});
    if (r.success) { result.success = true; result.count = atoi(r.msg.c_str()); }
    else result.error = r.error;
    return result;
}

/* ========== QQ凭证 + 统一心跳 ========== */

T3VariableResult T3Verify::getVariableByQq(const std::string& openid, const std::string& accessToken, const std::string& valueid, const std::string& valuename) {
    T3VariableResult result;
    auto r = simpleRequest(getVariableByQqCode_, "QQ获取变量", {{"openid", openid}, {"access_token", accessToken}, {"valueid", valueid}, {"valuename", valuename}});
    if (r.success) { result.success = true; result.value = r.msg; }
    else result.error = r.error;
    return result;
}

T3Result T3Verify::qqHeartbeat(const std::string& openid, const std::string& accessToken, const std::string& statecode) {
    return simpleRequest(qqHeartbeatCode_, "QQ心跳", {{"openid", openid}, {"access_token", accessToken}, {"statecode", statecode}});
}

T3CoreResult T3Verify::getUserCoreByQq(const std::string& openid, const std::string& accessToken) {
    T3CoreResult result;
    auto r = simpleRequest(getUserCoreByQqCode_, "QQ获取核心数据", {{"openid", openid}, {"access_token", accessToken}});
    if (r.success) { result.success = true; result.core = r.msg; }
    else result.error = r.error;
    return result;
}

T3Result T3Verify::modifyUserCoreByQq(const std::string& openid, const std::string& accessToken, const std::string& core) {
    return simpleRequest(modifyUserCoreByQqCode_, "QQ修改核心数据", {{"openid", openid}, {"access_token", accessToken}, {"core", core}});
}

T3Result T3Verify::unbindQq(const std::string& user, const std::string& pass) {
    return simpleRequest(unbindQqCode_, "解绑QQ", {{"user", user}, {"pass", pass}});
}

T3Result T3Verify::heartbeatAny(const std::string& statecode) {
    return simpleRequest(heartbeatAnyCode_, "统一心跳", {{"statecode", statecode}});
}
