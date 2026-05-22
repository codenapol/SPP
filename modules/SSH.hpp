#pragma once
#include <string>

class SSHSecurity {
public:
    static bool isRootLoginDisabled();
    static bool applyDisableRootLogin(bool disable);
    static bool revert();

private:
    static const std::string SSHD_CONFIG;
    static bool restartSSHD();
    static std::string trimLine(const std::string& s);
};
