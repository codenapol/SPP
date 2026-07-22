#pragma once
#include <string>

class DNSSecurity {
public:
    // Faux si systemd-resolved n'est pas le resolveur de la machine. La section
    // est alors masquee : sans ce garde-fou, chaque application comptait deux
    // echecs pour un module qui ne pouvait rien faire.
    static bool isAvailable();

    static bool isDNSSECEnabled();
    static bool isDNSOverTLSEnabled();
    static bool applyDNSSEC(bool enable);
    static bool applyDNSOverTLS(bool enable);

private:
    static std::string readKey(const std::string& key);
    static bool writeKey(const std::string& key, const std::string& value);
    static bool reloadResolved();
};
