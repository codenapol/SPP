#pragma once
#include <string>
#include <utility>
#include <vector>

struct SysctlOption {
    std::string name;
    std::string key;
    std::string hardened;
    std::string defaults;  // dernier recours ; l'etat reel capture par SppState prime
    std::string detail;
};

class KernelSecurity {
public:
    static bool apply(const SysctlOption& opt);
    static bool revert(const SysctlOption& opt);
    static bool isHardened(const SysctlOption& opt);

    // Une cle absente du noyau courant (LSM non charge, patch distro manquant)
    // ne doit ni etre affichee ni compter comme un echec.
    static bool exists(const SysctlOption& opt);
    static std::vector<SysctlOption> available(const std::vector<SysctlOption>& opts);

    static std::vector<SysctlOption> kernelOptions();
    static std::vector<SysctlOption> fsOptions();
    static std::vector<SysctlOption> netOptions();

    static bool writePersistenceConf(const std::vector<std::pair<std::string, std::string>>& entries);
    static bool removePersistenceConf();

    // Generique, partage avec NamespacesSecurity.
    static bool writeConf(const std::string& path,
                          const std::string& header,
                          const std::vector<std::pair<std::string, std::string>>& entries);

    static const std::string SYSCTL_CONF;

private:
    static std::string procPath(const std::string& key);

    // Une valeur ecrite dans net.*.conf.all.* n'atteint pas les interfaces deja
    // configurees : il faut aussi .conf.default.* et chaque interface presente.
    static std::vector<std::string> targetPaths(const SysctlOption& opt);

    static bool write(const SysctlOption& opt, const std::string& value);
};
