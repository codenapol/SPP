#include "SELinux.hpp"
#include "SafeFile.hpp"
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>

const std::string SELinuxSecurity::CONFIG_PATH  = "/etc/selinux/config";
const std::string SELinuxSecurity::ENFORCE_PATH = "/sys/fs/selinux/enforce";
const std::string SELinuxSecurity::BOOL_DIR     = "/sys/fs/selinux/booleans/";

// ─── utilitaires ──────────────────────────────────────────────────────────────

std::string SELinuxSecurity::trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// ─── mode enforcing ───────────────────────────────────────────────────────────

bool SELinuxSecurity::readMode() {
    std::ifstream f(ENFORCE_PATH);
    if (!f.is_open()) return false;
    std::string v;
    std::getline(f, v);
    return trim(v) == "1";
}

bool SELinuxSecurity::writeMode(bool enforcing) {
    // Runtime
    int rt = system(enforcing
        ? "setenforce 1 2>/dev/null"
        : "setenforce 0 2>/dev/null");

    // Persistance dans /etc/selinux/config
    std::ifstream fin(CONFIG_PATH);
    if (!fin.is_open()) return rt == 0;

    std::vector<std::string> lines;
    std::string line;
    bool found = false;

    while (std::getline(fin, line)) {
        auto t = trim(line);
        if (!t.empty() && t[0] != '#' &&
            t.rfind("SELINUX=", 0) == 0 &&
            t.rfind("SELINUXTYPE=", 0) != 0) {
            lines.push_back(std::string("SELINUX=") + (enforcing ? "enforcing" : "permissive"));
            found = true;
        } else {
            lines.push_back(line);
        }
    }
    fin.close();

    if (!found) return rt == 0;

    std::ostringstream out;
    for (const auto& l : lines) out << l << '\n';
    return SafeFile::writeAtomic(CONFIG_PATH, out.str());
}

// ─── booleans setsebool ───────────────────────────────────────────────────────

bool SELinuxSecurity::readBool(const std::string& name) {
    std::ifstream f(BOOL_DIR + name);
    if (!f.is_open()) return false;
    std::string v;
    std::getline(f, v);
    // format : "0 0" ou "1 1" — premier chiffre = valeur active
    return !v.empty() && v[0] == '1';
}

bool SELinuxSecurity::writeBool(const std::string& name, bool val) {
    // -P : persistant via selinux policy store
    std::string cmd = std::string("setsebool -P ") + name + (val ? " 1" : " 0") + " 2>/dev/null";
    return system(cmd.c_str()) == 0;
}

// ─── API publique ─────────────────────────────────────────────────────────────

bool SELinuxSecurity::isInstalled() {
    std::ifstream f(CONFIG_PATH);
    return f.is_open();
}

bool SELinuxSecurity::isHardened(const SELinuxOption& opt) {
    bool current = (opt.key == "mode") ? readMode() : readBool(opt.key);
    return current == opt.hardenedOn;
}

bool SELinuxSecurity::apply(const SELinuxOption& opt) {
    if (opt.key == "mode") return writeMode(opt.hardenedOn);
    return writeBool(opt.key, opt.hardenedOn);
}

bool SELinuxSecurity::revert(const SELinuxOption& opt) {
    if (opt.key == "mode") return writeMode(!opt.hardenedOn);
    return writeBool(opt.key, !opt.hardenedOn);
}

std::vector<SELinuxOption> SELinuxSecurity::available(const std::vector<SELinuxOption>& opts) {
    std::vector<SELinuxOption> out;
    for (const auto& opt : opts) {
        if (opt.key == "mode" || SafeFile::exists(BOOL_DIR + opt.key))
            out.push_back(opt);
    }
    return out;
}

// ─── listes d'options ─────────────────────────────────────────────────────────

std::vector<SELinuxOption> SELinuxSecurity::modeOptions() {
    return {
        {
            "Mode Enforcing",
            "mode", true,
            "Active le mode strict : toute action non couverte par la politique est"
            " bloquee et loguee. Protection maximale, meme pour root."
            " Le mode Permissif logue sans bloquer (utile pour l'audit)."
        },
    };
}

std::vector<SELinuxOption> SELinuxSecurity::booleanOptions() {
    return {
        {
            "Bloquer exec pile processus",
            "allow_execstack", false,
            "Interdit aux processus d'executer du code sur leur pile memoire."
            " Bloque les exploits de type stack buffer overflow avec shellcode."
        },
        {
            "Bloquer exec memoire anonyme",
            "allow_execmem", false,
            "Interdit les mappages memoire a la fois inscriptibles et executables."
            " Reduit fortement la surface d'exploitation des vulnerabilites memoire."
        },
        {
            "Mode securise (chargement modules)",
            "secure_mode_insmod", true,
            "Empeche le chargement et le dechargement de modules noyau en runtime."
            " Bloque les rootkits qui s'installent via insmod/modprobe."
        },
        {
            "Mode securise (recharg. politique)",
            "secure_mode_policyload", true,
            "Interdit le rechargement de la politique SELinux en cours d'execution."
            " Empeche un attaquant qui aurait root de modifier les regles SELinux."
        },
        {
            "Interdire ptrace inter-processus",
            "deny_ptrace", true,
            "Bloque ptrace entre processus non apparentes. Empeche l'injection de"
            " code dans un processus en cours d'execution, meme avec les droits root."
        },
    };
}
