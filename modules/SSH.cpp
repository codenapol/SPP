#include "SSH.hpp"
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>

const std::string SSHSecurity::SSHD_CONFIG = "/etc/ssh/sshd_config";

std::string SSHSecurity::trimLine(const std::string& s) {
    size_t start = s.find_first_not_of(" \t");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

bool SSHSecurity::restartSSHD() {
    int r = system("systemctl restart sshd 2>/dev/null");
    if (r != 0)
        r = system("systemctl restart ssh 2>/dev/null");
    return r == 0;
}

bool SSHSecurity::isRootLoginDisabled() {
    std::ifstream f(SSHD_CONFIG);
    if (!f.is_open()) return false;
    std::string line;
    while (std::getline(f, line)) {
        auto t = trimLine(line);
        if (t.empty() || t[0] == '#') continue;
        if (t.rfind("PermitRootLogin", 0) != 0) continue;
        auto pos = t.find_first_of(" \t", 15);
        if (pos == std::string::npos) continue;
        return trimLine(t.substr(pos)) == "no";
    }
    return false;
}

bool SSHSecurity::applyDisableRootLogin(bool disable) {
    std::ifstream fin(SSHD_CONFIG);
    if (!fin.is_open()) return false;

    std::vector<std::string> lines;
    std::string line;
    bool found = false;

    while (std::getline(fin, line)) {
        // Correspond a la directive, commentee ou non
        auto stripped = trimLine(line);
        if (!stripped.empty() && stripped[0] == '#')
            stripped = trimLine(stripped.substr(1));

        if (stripped.rfind("PermitRootLogin", 0) == 0) {
            lines.push_back(std::string("PermitRootLogin ") + (disable ? "no" : "yes"));
            found = true;
        } else {
            lines.push_back(line);
        }
    }
    fin.close();

    if (!found)
        lines.push_back(std::string("PermitRootLogin ") + (disable ? "no" : "yes"));

    std::ofstream fout(SSHD_CONFIG);
    if (!fout.is_open()) return false;
    for (const auto& l : lines)
        fout << l << '\n';
    if (!fout.good()) return false;
    fout.close();

    return restartSSHD();
}

bool SSHSecurity::revert() {
    return applyDisableRootLogin(false);
}
