#pragma once
#include <string>

class SSHSecurity {
public:
    // Faux s'il n'y a pas de serveur SSH : la section est alors masquee plutot
    // que de compter un echec a chaque application.
    static bool isInstalled();

    static bool isRootLoginDisabled();
    static bool applyDisableRootLogin(bool disable);

    // Retire la configuration posee par SPP. N'ecrit jamais "PermitRootLogin yes" :
    // desinstaller SPP ne doit pas ouvrir un acces root qui etait ferme.
    static bool revert();

private:
    static const std::string SSHD_CONFIG;
    static const std::string DROPIN_DIR;
    static const std::string DROPIN_FILE;

    static bool useDropIn();                        // le sshd_config a-t-il un Include ?
    static bool validateConfig();                   // sshd -t
    static bool restartSSHD();
    static bool readDirectiveFrom(const std::string& path, bool& disabled);
};
