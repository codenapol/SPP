#include "AppArmor.hpp"
#include "SafeFile.hpp"
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>

const std::string AppArmorSecurity::ENABLED_PATH  = "/sys/module/apparmor/parameters/enabled";
const std::string AppArmorSecurity::PROFILES_PATH = "/sys/kernel/security/apparmor/profiles";
const std::string AppArmorSecurity::PROFILES_DIR  = "/etc/apparmor.d/";

// ─── utilitaires ──────────────────────────────────────────────────────────────

std::string AppArmorSecurity::trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// ─── enforce all ──────────────────────────────────────────────────────────────

bool AppArmorSecurity::readEnforceAll() {
    std::ifstream f(PROFILES_PATH);
    if (!f.is_open()) return false;
    std::string line;
    bool any = false;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        any = true;
        if (line.find("(complain)") != std::string::npos ||
            line.find("(disabled)") != std::string::npos)
            return false;
    }
    return any;
}

bool AppArmorSecurity::writeEnforceAll(bool enforce) {
    // Le glob /etc/apparmor.d/* remontait aussi abstractions/, tunables/ et
    // local/ : aa-enforce sortait en erreur, l'operation echouait toujours.
    std::string cmd = std::string("find /etc/apparmor.d -maxdepth 1 -type f -exec ")
                    + (enforce ? "aa-enforce" : "aa-complain")
                    + " {} + >/dev/null 2>&1";
    return system(cmd.c_str()) == 0;
}

// ─── profil individuel ────────────────────────────────────────────────────────

bool AppArmorSecurity::readProfile(const std::string& binPath) {
    std::ifstream f(PROFILES_PATH);
    if (!f.is_open()) return false;
    std::string line;
    while (std::getline(f, line)) {
        // format : "/usr/sbin/sshd (enforce)"
        if (line.find(binPath) != std::string::npos)
            return line.find("(enforce)") != std::string::npos;
    }
    return false;
}

bool AppArmorSecurity::writeProfile(const std::string& key, bool enforce) {
    std::string profilePath = PROFILES_DIR + key;
    std::string cmd = (enforce ? "aa-enforce " : "aa-complain ") + profilePath + " 2>/dev/null";
    return system(cmd.c_str()) == 0;
}

// ─── API publique ─────────────────────────────────────────────────────────────

bool AppArmorSecurity::isInstalled() {
    std::ifstream f(ENABLED_PATH);
    if (!f.is_open()) return false;
    std::string v;
    std::getline(f, v);
    return trim(v) == "Y" || trim(v) == "1";
}

bool AppArmorSecurity::isHardened(const AppArmorOption& opt) {
    bool current = (opt.key == "enforce_all")
        ? readEnforceAll()
        : readProfile(opt.binPath);
    return current == opt.hardenedOn;
}

bool AppArmorSecurity::apply(const AppArmorOption& opt) {
    if (opt.key == "enforce_all") return writeEnforceAll(opt.hardenedOn);
    return writeProfile(opt.key, opt.hardenedOn);
}

bool AppArmorSecurity::revert(const AppArmorOption& opt) {
    if (opt.key == "enforce_all") return writeEnforceAll(!opt.hardenedOn);
    return writeProfile(opt.key, !opt.hardenedOn);
}

// Les profils listes ici ne sont pas tous installes : sbin.dhclient n'existe
// pas sur un systeme merged-/usr, usr.bin.firefox pas sur Debian. Les afficher
// produisait des echecs pour des profils simplement absents.
std::vector<AppArmorOption> AppArmorSecurity::available(const std::vector<AppArmorOption>& opts) {
    std::vector<AppArmorOption> out;
    for (const auto& opt : opts) {
        if (opt.key == "enforce_all" || SafeFile::exists(PROFILES_DIR + opt.key))
            out.push_back(opt);
    }
    return out;
}

// ─── listes d'options ─────────────────────────────────────────────────────────

std::vector<AppArmorOption> AppArmorSecurity::enforcementOptions() {
    return {
        {
            "Enforcer tous les profils",
            "enforce_all", "",
            true,
            "Bascule tous les profils AppArmor charges en mode enforce."
            " Bloque toute action non autorisee par la politique, pour chaque"
            " application confinee. Le mode complain logue sans bloquer."
        },
    };
}

std::vector<AppArmorOption> AppArmorSecurity::profileOptions() {
    return {
        {
            "SSH daemon (sshd)",
            "usr.sbin.sshd", "/usr/sbin/sshd",
            true,
            "Confine sshd en mode enforce : limite les acces fichiers, reseau et"
            " syscalls autorises. Reduit la surface d'attaque en cas d'exploit SSH."
        },
        {
            "Client DHCP (dhclient)",
            "sbin.dhclient", "/sbin/dhclient",
            true,
            "Confine dhclient qui tourne en root lors de la negociation reseau."
            " Empeche un serveur DHCP malveillant d'executer du code arbitraire."
        },
        {
            "DNS (dnsmasq)",
            "usr.sbin.dnsmasq", "/usr/sbin/dnsmasq",
            true,
            "Confine dnsmasq : restreint les acces en dehors de sa fonction DNS/DHCP."
            " Limite l'impact d'une exploitation via requetes DNS forgees."
        },
        {
            "Impression (cupsd)",
            "usr.sbin.cupsd", "/usr/sbin/cupsd",
            true,
            "Confine le daemon d'impression CUPS. Empeche l'acces a des ressources"
            " systeme hors perimetre, malgre les nombreux vecteurs d'attaque connus."
        },
        {
            "Pages de manuel (man)",
            "usr.bin.man", "/usr/bin/man",
            true,
            "Confine la commande man et ses pipelines (groff, nroff...)."
            " Empeche l'execution de code via un fichier de manuel piege."
        },
        {
            "Visionneuse PDF (evince)",
            "usr.bin.evince", "/usr/bin/evince",
            true,
            "Confine Evince lors de l'ouverture de documents PDF ou PostScript."
            " Limite les acces fichiers et reseau exploitables via un PDF malveillant."
        },
        {
            "Capture reseau (tcpdump)",
            "usr.sbin.tcpdump", "/usr/sbin/tcpdump",
            true,
            "Confine tcpdump qui necessite des privileges elevés."
            " Restreint ce qu'il peut faire avec les paquets captures."
        },
        {
            "Navigateur Firefox",
            "usr.bin.firefox", "/usr/bin/firefox",
            true,
            "Confine Firefox : restreint l'acces au systeme de fichiers et aux"
            " appels systeme. Renforce le sandboxing natif contre les exploits web."
        },
        {
            "Client mail (thunderbird)",
            "usr.bin.thunderbird", "/usr/bin/thunderbird",
            true,
            "Confine Thunderbird : limite l'acces fichiers hors profil utilisateur."
            " Bloque les acces non autorises via pieces jointes ou emails malveillants."
        },
    };
}
