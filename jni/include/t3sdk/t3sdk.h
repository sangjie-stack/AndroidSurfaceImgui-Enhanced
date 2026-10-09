/**
 * T3验证SDK - C++版本
 * 官网: https://www.t3yanzheng.com
 * 
 * 纯C++实现，不依赖OpenSSL，支持Base64和RSA双算法
 */

#ifndef T3SDK_H
#define T3SDK_H

#include <string>
#include <vector>
#include <cstdint>
#include <map>

/* ========== 结果结构体 ========== */

struct T3Result {
    bool success = false;
    std::string error;
    std::string msg;
};

struct T3LoginResult {
    bool success = false;
    std::string error;
    std::string id;
    std::string end_time;
    std::string statecode;
    std::string recharge;
    std::string use_time;
    std::string amount;
    std::string available;
    std::string imei;
    std::string change;
    std::string core;
};

struct T3NoticeResult {
    bool success = false;
    std::string error;
    std::string notice;
};

struct T3VersionResult {
    bool success = false;
    std::string error;
    std::string version;
};

struct T3QueryResult {
    bool success = false;
    std::string error;
    std::string state;
    std::string use;
    std::string id;
    std::string use_time;
    std::string end_time;
    std::string line_time;
    std::string line;
    std::string amount;
    std::string available;
};

struct T3UpdateResult {
    bool success = false;
    std::string error;
    bool hasUpdate = false;
    std::string ver;
    std::string version;
    std::string uplog;
    std::string upurl;
    std::string msg;
};

struct T3VariableResult {
    bool success = false;
    std::string error;
    std::string value;
};

struct T3CloudDocResult {
    bool success = false;
    std::string error;
    std::string content;
};

struct T3CoreResult {
    bool success = false;
    std::string error;
    std::string core;
};

struct T3OnlineResult {
    bool success = false;
    std::string error;
    int count = 0;
};

struct T3AppSignResult {
    bool success = false;
    std::string error;
    std::string msg;
    std::string autograph;
    long time = 0;
};


/* ========== CustomBase64 编解码器 ========== */

class CustomBase64 {
public:
    explicit CustomBase64(const std::string& customCharset);
    std::string encode(const std::string& data) const;
    std::string decode(const std::string& data) const;
    std::string encodeToHex(const std::string& data) const;
private:
    static const std::string STANDARD_CHARSET;
    std::string customCharset_;
};


/* ========== RSA加解密器(不依赖OpenSSL) ========== */

class RSACrypto {
public:
    explicit RSACrypto(const std::string& publicKeyPem);
    std::vector<uint8_t> encrypt(const std::string& data) const;
    std::string decrypt(const std::vector<uint8_t>& encryptedData) const;
    std::string encryptToHex(const std::string& data) const;
    std::string decryptFromBase64(const std::string& base64Str) const;
private:
    struct BigNum;
    struct RSAKey;
    RSAKey* key_;
    int keySize_;
    int encryptBlockSize_;
    int decryptBlockSize_;
    void parsePEM(const std::string& pem);
};


/* ========== T3验证SDK主类 ========== */

class T3Verify {
public:
    T3Verify();
    ~T3Verify();
    
    /* 初始化 (Base64模式) */
    bool init(const std::string& loginCode, const std::string& noticeCode,
              const std::string& versionCode, const std::string& heartbeatCode,
              const std::string& appkey, const std::string& base64Charset);
    
    /* 初始化 (RSA模式) */
    bool initRSA(const std::string& loginCode, const std::string& noticeCode,
                 const std::string& versionCode, const std::string& heartbeatCode,
                 const std::string& appkey, const std::string& rsaPublicKey);
    
    /* 设置新增调用码 */
    void setCode(const std::string& field, const std::string& code);
    
    /* ===== 卡密验证 ===== */
    T3LoginResult login(const std::string& kami, const std::string& imei);
    T3QueryResult queryKami(const std::string& kami);
    T3Result heartbeat(const std::string& kami, const std::string& statecode);
    
    /* ===== 数据与内容 ===== */
    T3NoticeResult getNotice();
    T3VersionResult getLatestVersion();
    T3UpdateResult checkUpdate(const std::string& ver);
    T3CloudDocResult getCloudDoc(const std::string& token);
    T3AppSignResult appSign(const std::string& autograph);
    
    /* ===== 用户体系 ===== */
    T3Result userRegister(const std::string& user, const std::string& pass, const std::string& email = "");
    T3LoginResult userLogin(const std::string& user, const std::string& pass, const std::string& imei);
    T3Result userHeartbeat(const std::string& user, const std::string& pass, const std::string& statecode);
    T3LoginResult qqLogin(const std::string& openid, const std::string& accessToken);
    T3Result bindQQ(const std::string& user, const std::string& pass, const std::string& openid, const std::string& accessToken);
    T3Result changePassword(const std::string& user, const std::string& oldpass, const std::string& newpass);
    T3Result userCancel(const std::string& user, const std::string& pass);
    T3Result recharge(const std::string& user, const std::string& card);
    T3Result kamiRecharge(const std::string& targetKami, const std::string& sourceKami);
    
    /* ===== 设备与安全 ===== */
    T3Result unbindKami(const std::string& kami, const std::string& imei);
    T3Result unbindUser(const std::string& user, const std::string& pass, const std::string& imei);
    T3Result ipUnbindKami(const std::string& kami);
    T3Result ipUnbindUser(const std::string& user, const std::string& pass);
    T3Result disableKami(const std::string& kami);
    T3Result disableUser(const std::string& user, const std::string& pass);
    
    /* ===== 远程变量 ===== */
    T3VariableResult getVariableByKami(const std::string& kami, const std::string& valueid, const std::string& valuename);
    T3VariableResult getVariableByUser(const std::string& user, const std::string& pass, const std::string& valueid, const std::string& valuename);
    T3Result modifyVariableByKami(const std::string& kami, const std::string& valueid, const std::string& valuecontent);
    T3Result modifyVariableByUser(const std::string& user, const std::string& pass, const std::string& valueid, const std::string& valuecontent);
    
    /* ===== 核心数据 ===== */
    T3Result modifyCoreByKami(const std::string& kami, const std::string& core);
    T3Result modifyCoreByUser(const std::string& user, const std::string& pass, const std::string& core);
    T3CoreResult getCoreByKami(const std::string& kami);
    T3CoreResult getCoreByUser(const std::string& user, const std::string& pass);
    
    /* ===== 在线数量 ===== */
    T3OnlineResult getOnlineKamiCount();
    T3OnlineResult getOnlineUserCount();

    /* ===== QQ凭证 + 统一心跳 ===== */
    T3VariableResult getVariableByQq(const std::string& openid, const std::string& accessToken, const std::string& valueid, const std::string& valuename);
    T3Result qqHeartbeat(const std::string& openid, const std::string& accessToken, const std::string& statecode);
    T3CoreResult getUserCoreByQq(const std::string& openid, const std::string& accessToken);
    T3Result modifyUserCoreByQq(const std::string& openid, const std::string& accessToken, const std::string& core);
    T3Result unbindQq(const std::string& user, const std::string& pass);
    T3Result heartbeatAny(const std::string& statecode);

private:
    std::vector<std::string> serverUrls_;
    std::string serverUrl_;
    std::string loginCode_, noticeCode_, versionCode_, heartbeatCode_;
    std::string queryCode_, registerCode_, userLoginCode_, userHeartbeatCode_;
    std::string qqLoginCode_, bindQQCode_, changePasswordCode_, userCancelCode_;
    std::string rechargeCode_, kamiRechargeCode_, unbindCode_, ipUnbindCode_, disableCode_;
    std::string checkUpdateCode_, getVariableCode_, modifyVariableCode_, modifyCoreCode_;
    std::string getKamiCoreCode_, getUserCoreCode_, onlineKamiCode_, onlineUserCode_;
    std::string cloudDocCode_, appSignCode_;
    std::string getVariableByQqCode_, qqHeartbeatCode_, getUserCoreByQqCode_;
    std::string modifyUserCoreByQqCode_, unbindQqCode_, heartbeatAnyCode_;
    std::string appkey_;
    int encodeType_;
    bool initialized_;
    std::string statecode_, endTime_;
    CustomBase64* encoder_;
    RSACrypto* rsaCrypto_;
    
    void checkInit() const;
    std::string buildUrl(const std::string& code) const;
    std::string encodeValue(const std::string& value) const;
    std::string decodeResponse(const std::string& responseText) const;
    
    std::pair<std::vector<std::pair<std::string, std::string>>, std::string> 
    encodeParams(const std::vector<std::pair<std::string, std::string>>& params) const;
    
    std::string httpPost(const std::string& url, 
                         const std::vector<std::pair<std::string, std::string>>& data);
    
    /* 通用简单请求 */
    T3Result simpleRequest(const std::string& code, const std::string& codeName,
                           const std::vector<std::pair<std::string, std::string>>& params);
};


/* ========== 工具函数 ========== */

std::string getMachineCode();

#endif /* T3SDK_H */
