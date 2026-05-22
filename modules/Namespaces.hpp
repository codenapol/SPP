#pragma once
#include <string>
#include <vector>
#include <utility>

struct NamespaceOption {
    std::string name;
    std::string key;
    std::string hardened;
    std::string defaults;
    std::string detail;
};

class NamespacesSecurity {
public:
    static std::vector<NamespaceOption> options();
    static bool apply(const NamespaceOption& opt);
    static bool revert(const NamespaceOption& opt);
    static bool isHardened(const NamespaceOption& opt);

    static bool writePersistenceConf(const std::vector<std::pair<std::string,std::string>>& entries);
    static bool removePersistenceConf();

    static const std::string SYSCTL_CONF;

private:
    static std::string procPath(const std::string& key);
    static std::string readValue(const std::string& path);
    static bool        writeValue(const std::string& path, const std::string& value);
};
