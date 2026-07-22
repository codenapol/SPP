#pragma once
#include <string>
#include <vector>

struct AppArmorOption {
    std::string name;       // nom affiché
    std::string key;        // "enforce_all" ou nom de fichier profil (ex: "usr.sbin.sshd")
    std::string binPath;    // chemin binaire tel que vu dans le fichier profiles (vide si enforce_all)
    bool        hardenedOn; // true = mode enforce = état durci
    std::string detail;
};

class AppArmorSecurity {
public:
    static bool isInstalled();

    static std::vector<AppArmorOption> enforcementOptions();
    static std::vector<AppArmorOption> profileOptions();

    // Ecarte les profils absents de /etc/apparmor.d/ : ils ne peuvent pas etre
    // appliques et n'ont donc rien a faire dans l'interface.
    static std::vector<AppArmorOption> available(const std::vector<AppArmorOption>& opts);

    static bool isHardened(const AppArmorOption& opt);
    static bool apply(const AppArmorOption& opt);
    static bool revert(const AppArmorOption& opt);

private:
    static const std::string ENABLED_PATH;
    static const std::string PROFILES_PATH;
    static const std::string PROFILES_DIR;

    static bool readEnforceAll();
    static bool writeEnforceAll(bool enforce);

    static bool readProfile(const std::string& binPath);
    static bool writeProfile(const std::string& key, bool enforce);

    static std::string trim(const std::string& s);
};
