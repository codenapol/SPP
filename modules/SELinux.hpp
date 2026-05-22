#pragma once
#include <string>
#include <vector>

struct SELinuxOption {
    std::string name;
    std::string key;        // "mode" pour enforcing/permissif, ou nom du boolean setsebool
    bool        hardenedOn; // true = valeur securisee = 1 (actif), false = valeur securisee = 0 (inactif)
    std::string detail;
};

class SELinuxSecurity {
public:
    static bool isInstalled();

    static std::vector<SELinuxOption> modeOptions();
    static std::vector<SELinuxOption> booleanOptions();

    static bool isHardened(const SELinuxOption& opt);
    static bool apply(const SELinuxOption& opt);
    static bool revert(const SELinuxOption& opt);

private:
    static const std::string CONFIG_PATH;
    static const std::string ENFORCE_PATH;
    static const std::string BOOL_DIR;

    static bool readMode();
    static bool writeMode(bool enforcing);

    static bool readBool(const std::string& name);
    static bool writeBool(const std::string& name, bool val);

    static std::string trim(const std::string& s);
};
