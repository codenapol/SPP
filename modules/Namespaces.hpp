#pragma once
#include "Kernel.hpp"

// Les namespaces se pilotent par sysctl comme le reste : NamespaceOption etait
// un clone exact de SysctlOption, et l'implementation un copier-coller integral
// de Kernel.cpp. Tout est delegue, seule la liste d'options est specifique.
using NamespaceOption = SysctlOption;

class NamespacesSecurity {
public:
    static std::vector<NamespaceOption> options();

    static bool apply(const NamespaceOption& opt)      { return KernelSecurity::apply(opt); }
    static bool revert(const NamespaceOption& opt)     { return KernelSecurity::revert(opt); }
    static bool isHardened(const NamespaceOption& opt) { return KernelSecurity::isHardened(opt); }

    static std::vector<NamespaceOption> available(const std::vector<NamespaceOption>& opts) {
        return KernelSecurity::available(opts);
    }

    static bool writePersistenceConf(const std::vector<std::pair<std::string, std::string>>& entries) {
        return KernelSecurity::writeConf(SYSCTL_CONF, "SPP - Isolation par namespaces", entries);
    }
    static bool removePersistenceConf();

    static const std::string SYSCTL_CONF;
};
