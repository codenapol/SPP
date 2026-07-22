#include "SSH.hpp"
#include "SafeFile.hpp"

#include <sstream>
#include <vector>
#include <cerrno>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>

const std::string SSHSecurity::SSHD_CONFIG = "/etc/ssh/sshd_config";
const std::string SSHSecurity::DROPIN_DIR  = "/etc/ssh/sshd_config.d";
const std::string SSHSecurity::DROPIN_FILE = "/etc/ssh/sshd_config.d/99-spp.conf";

// ─── detection ────────────────────────────────────────────────────────────────

bool SSHSecurity::isInstalled() {
    return SafeFile::exists("/usr/sbin/sshd") || SafeFile::exists("/usr/bin/sshd");
}

// OpenSSH retient la PREMIERE valeur rencontree. Le "Include sshd_config.d/*.conf"
// figure en tete du fichier Debian/Ubuntu : un drop-in y prime donc sur toute
// directive du fichier principal, qu'on n'a alors plus besoin de modifier.
bool SSHSecurity::useDropIn() {
    std::istringstream in(SafeFile::read(SSHD_CONFIG));
    std::string line;
    while (std::getline(in, line)) {
        const std::string t = SafeFile::trim(line);
        if (t.empty() || t[0] == '#') continue;
        if (t.rfind("Include", 0) != 0) continue;
        if (t.find("sshd_config.d") != std::string::npos) return true;
    }
    return false;
}

// ─── lecture de l'etat ────────────────────────────────────────────────────────

bool SSHSecurity::readDirectiveFrom(const std::string& path, bool& disabled) {
    std::istringstream in(SafeFile::read(path));
    std::string line;
    while (std::getline(in, line)) {
        std::string t = SafeFile::trim(line);
        if (t.empty() || t[0] == '#') continue;
        if (t.rfind("PermitRootLogin", 0) != 0) continue;

        std::string rest = SafeFile::trim(t.substr(15));
        if (!rest.empty() && rest[0] == '=')
            rest = SafeFile::trim(rest.substr(1));
        if (rest.empty()) continue;  // "PermitRootLoginXxx", pas notre directive

        auto end = rest.find_first_of(" \t");
        disabled = (rest.substr(0, end) == "no");
        return true;
    }
    return false;
}

bool SSHSecurity::isRootLoginDisabled() {
    bool disabled = false;
    // Le drop-in gagne, il est donc consulte en premier.
    if (readDirectiveFrom(DROPIN_FILE, disabled)) return disabled;
    if (readDirectiveFrom(SSHD_CONFIG, disabled)) return disabled;
    return false;
}

// ─── validation et rechargement ───────────────────────────────────────────────

bool SSHSecurity::validateConfig() {
    return std::system("sshd -t 2>/dev/null") == 0 ||
           std::system("/usr/sbin/sshd -t 2>/dev/null") == 0;
}

bool SSHSecurity::restartSSHD() {
    // Un service a l'arret n'a rien a recharger : le signaler comme un echec
    // faussait le compteur a chaque application.
    if (std::system("systemctl is-active --quiet ssh 2>/dev/null") == 0)
        return std::system("systemctl reload-or-restart ssh 2>/dev/null") == 0;
    if (std::system("systemctl is-active --quiet sshd 2>/dev/null") == 0)
        return std::system("systemctl reload-or-restart sshd 2>/dev/null") == 0;
    return true;
}

// ─── application ──────────────────────────────────────────────────────────────

bool SSHSecurity::applyDisableRootLogin(bool disable) {
    if (!isInstalled()) return true;

    if (!disable) return revert();

    if (useDropIn()) {
        ::mkdir(DROPIN_DIR.c_str(), 0755);
        const std::string content =
            "# SPP - Systeme de Protection Patriote\n"
            "# Supprimer ce fichier suffit a revenir a la configuration d'origine.\n"
            "PermitRootLogin no\n";
        if (!SafeFile::writeAtomic(DROPIN_FILE, content, 0600))
            return false;

        // Une config invalide tue sshd au rechargement : on retire notre
        // fichier avant de toucher au service.
        if (!validateConfig()) {
            ::unlink(DROPIN_FILE.c_str());
            return false;
        }
        return restartSSHD();
    }

    // Pas de directive Include : on modifie le fichier principal, apres l'avoir
    // sauvegarde une fois pour toutes.
    if (!SafeFile::backupOnce(SSHD_CONFIG)) return false;

    std::istringstream in(SafeFile::read(SSHD_CONFIG));
    std::ostringstream out;
    std::string line;
    bool found = false;

    while (std::getline(in, line)) {
        std::string stripped = SafeFile::trim(line);
        if (!stripped.empty() && stripped[0] == '#')
            stripped = SafeFile::trim(stripped.substr(1));

        if (stripped.rfind("PermitRootLogin", 0) == 0 && !found) {
            out << "PermitRootLogin no\n";
            found = true;
        } else if (stripped.rfind("PermitRootLogin", 0) == 0) {
            out << "# " << line << '\n';  // doublons neutralises
        } else {
            out << line << '\n';
        }
    }
    if (!found)
        out << "PermitRootLogin no\n";

    if (!SafeFile::writeAtomic(SSHD_CONFIG, out.str())) return false;
    if (!validateConfig()) {
        SafeFile::restoreBackup(SSHD_CONFIG);
        return false;
    }
    return restartSSHD();
}

bool SSHSecurity::revert() {
    if (!isInstalled()) return true;

    bool changed = false;

    if (::unlink(DROPIN_FILE.c_str()) == 0)
        changed = true;
    else if (errno != ENOENT)
        return false;

    if (SafeFile::exists(SSHD_CONFIG + SafeFile::BACKUP_SUFFIX)) {
        if (!SafeFile::restoreBackup(SSHD_CONFIG)) return false;
        changed = true;
    }

    if (!changed) return true;  // SPP n'avait rien pose
    if (!validateConfig()) return false;
    return restartSSHD();
}
