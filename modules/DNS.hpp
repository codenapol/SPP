#pragma once
#include <string>

class DNSSecurity {
public:
    static bool isDNSSECEnabled();
    static bool isDNSOverTLSEnabled();
    static bool applyDNSSEC(bool enable);
    static bool applyDNSOverTLS(bool enable);

private:
    static std::string readKey(const std::string& key);
    static bool writeKey(const std::string& key, const std::string& value);
};
