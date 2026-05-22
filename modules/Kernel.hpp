#pragma once
#include <string>
#include <vector>
#include <utility>

struct SysctlOption {
    std::string name;
    std::string key;
    std::string hardened;
    std::string defaults;
    std::string detail;
};

class KernelSecurity {
public:
    static bool apply(const SysctlOption& opt);
    static bool revert(const SysctlOption& opt);
    static bool isHardened(const SysctlOption& opt);

    static std::vector<SysctlOption> kernelOptions();
    static std::vector<SysctlOption> fsOptions();
    static std::vector<SysctlOption> netOptions();

    static bool writePersistenceConf(const std::vector<std::pair<std::string,std::string>>& entries);
    static bool removePersistenceConf();

    static const std::string SYSCTL_CONF;

private:
    static std::string procPath(const std::string& key);
    static std::string readValue(const std::string& path);
    static bool writeValue(const std::string& path, const std::string& value);
};
