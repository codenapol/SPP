#include "Kernel.hpp"
#include "SafeFile.hpp"
#include "State.hpp"

#include <sstream>
#include <cerrno>
#include <dirent.h>
#include <unistd.h>

const std::string KernelSecurity::SYSCTL_CONF = "/etc/sysctl.d/99-spp.conf";

// ─── persistance ──────────────────────────────────────────────────────────────

bool KernelSecurity::writeConf(const std::string& path,
                               const std::string& header,
                               const std::vector<std::pair<std::string, std::string>>& entries) {
    if (entries.empty())
        return ::unlink(path.c_str()) == 0 || errno == ENOENT;

    std::ostringstream out;
    out << "# " << header << '\n';
    for (const auto& [key, val] : entries)
        out << key << " = " << val << '\n';

    return SafeFile::writeAtomic(path, out.str(), 0644);
}

bool KernelSecurity::writePersistenceConf(const std::vector<std::pair<std::string, std::string>>& entries) {
    return writeConf(SYSCTL_CONF, "SPP - Systeme de Protection Patriote", entries);
}

bool KernelSecurity::removePersistenceConf() {
    return ::unlink(SYSCTL_CONF.c_str()) == 0 || errno == ENOENT;
}

// ─── resolution des chemins ───────────────────────────────────────────────────

std::string KernelSecurity::procPath(const std::string& key) {
    std::string path = "/proc/sys/";
    for (char c : key)
        path += (c == '.' ? '/' : c);
    return path;
}

std::vector<std::string> KernelSecurity::targetPaths(const SysctlOption& opt) {
    const std::string primary = procPath(opt.key);
    std::vector<std::string> paths{ primary };

    // net.*.conf.all.X ne s'applique pas aux interfaces deja configurees :
    // sans ce fan-out, "Desactiver IPv6" ne desactive pas IPv6 sur eth0.
    static const std::string kMarker = "/conf/all/";
    const auto pos = primary.find(kMarker);
    if (pos == std::string::npos)
        return paths;

    const std::string base = primary.substr(0, pos + 6);  // ".../conf/"
    const std::string leaf = primary.substr(pos + kMarker.size());

    DIR* dir = ::opendir(base.c_str());
    if (!dir) return paths;
    while (dirent* entry = ::readdir(dir)) {
        const std::string name = entry->d_name;
        if (name == "." || name == ".." || name == "all") continue;
        paths.push_back(base + name + "/" + leaf);  // "default" et chaque interface
    }
    ::closedir(dir);
    return paths;
}

// ─── lecture / ecriture ───────────────────────────────────────────────────────

bool KernelSecurity::write(const SysctlOption& opt, const std::string& value) {
    if (value.empty()) return false;

    const auto paths = targetPaths(opt);
    if (paths.empty()) return false;

    // Capture l'etat d'origine avant de l'ecraser. Sans appel prealable a
    // recordOriginal(), aucune restauration fidele n'est possible.
    SppState::recordOriginal(opt.key, SafeFile::readLine(paths.front()));

    // La cle primaire fait foi ; le fan-out sur les interfaces est best-effort
    // (une interface peut disparaitre entre l'enumeration et l'ecriture).
    bool ok = SafeFile::writeProc(paths.front(), value);
    for (size_t i = 1; i < paths.size(); ++i)
        SafeFile::writeProc(paths[i], value);
    return ok;
}

bool KernelSecurity::apply(const SysctlOption& opt) {
    return write(opt, opt.hardened);
}

bool KernelSecurity::revert(const SysctlOption& opt) {
    // Aucun original enregistre = SPP n'a jamais touche cette cle : elle etait
    // deja dans cet etat. Ne rien faire est le seul comportement sur, la colonne
    // `defaults` ne refletant pas la realite de la distribution.
    if (!SppState::hasOriginal(opt.key))
        return true;

    const std::string orig = SppState::original(opt.key);
    return write(opt, orig.empty() ? opt.defaults : orig);
}

bool KernelSecurity::isHardened(const SysctlOption& opt) {
    if (!exists(opt)) return false;
    for (const auto& path : targetPaths(opt)) {
        if (!SafeFile::exists(path)) continue;
        if (SafeFile::readLine(path) != opt.hardened) return false;
    }
    return true;
}

bool KernelSecurity::exists(const SysctlOption& opt) {
    return SafeFile::exists(procPath(opt.key));
}

std::vector<SysctlOption> KernelSecurity::available(const std::vector<SysctlOption>& opts) {
    std::vector<SysctlOption> out;
    for (const auto& opt : opts)
        if (exists(opt)) out.push_back(opt);
    return out;
}

std::vector<SysctlOption> KernelSecurity::kernelOptions() {
    return {
        {
            "ASLR complet",
            "kernel.randomize_va_space", "2", "1",
            "Randomise les adresses memoire des processus. Un exploit buffer overflow"
            " ne peut pas predire ou atterrir en memoire."
        },
        {
            "Restreindre dmesg",
            "kernel.dmesg_restrict", "1", "0",
            "Masque les logs kernel aux non-root. Ces logs contiennent des adresses"
            " memoire et infos systeme utiles a un attaquant."
        },
        {
            "Masquer pointeurs kernel",
            "kernel.kptr_restrict", "2", "0",
            "Cache les adresses kernel dans /proc/kallsyms. Sans ca, n'importe quel"
            " utilisateur peut voir ou sont chargees les fonctions kernel."
        },
        {
            "Restreindre ptrace",
            "kernel.yama.ptrace_scope", "2", "0",
            "Seul root peut attacher un debugger a un processus. Bloque les attaques"
            " d'injection dans des processus en cours d'execution."
        },
        {
            "Desactiver BPF non-root",
            "kernel.unprivileged_bpf_disabled", "1", "0",
            "BPF (Berkeley Packet Filter) est tres puissant et vecteur de nombreuses"
            " CVEs recentes. Desactive pour les utilisateurs normaux."
        },
        {
            "Restreindre perf events",
            "kernel.perf_event_paranoid", "3", "1",
            "Restreint l'acces aux compteurs de performance CPU. Reduit les attaques"
            " side-channel de type Spectre utilisant ces compteurs."
        },
        {
            "Core dumps avec PID",
            "kernel.core_uses_pid", "1", "0",
            "Ajoute le PID dans le nom des fichiers core dump. Evite qu'un dump"
            " en ecrase un autre, utile pour l'audit forensique."
        },
        {
            "Bloquer autoload TTY",
            "dev.tty.ldisc_autoload", "0", "1",
            "Empeche le chargement automatique des line disciplines TTY non-root."
            " Bloque un vecteur d'exploitation peu connu permettant le chargement"
            " de modules noyau non autorises."
        },
    };
}

std::vector<SysctlOption> KernelSecurity::fsOptions() {
    return {
        {
            "Bloquer dumps SUID",
            "fs.suid_dumpable", "0", "1",
            "Empeche les programmes SUID (qui tournent en root) de generer des core"
            " dumps pouvant contenir des cles ou mots de passe en memoire."
        },
        {
            "Protection hardlinks",
            "fs.protected_hardlinks", "1", "0",
            "Empeche de creer un hardlink vers un fichier non-possede. Bloque les"
            " attaques TOCTOU (Time-Of-Check Time-Of-Use)."
        },
        {
            "Protection symlinks",
            "fs.protected_symlinks", "1", "0",
            "Empeche de suivre un symlink d'un autre utilisateur dans /tmp. Bloque"
            " les attaques de race condition classiques sur les repertoires partagés."
        },
        {
            "Protection FIFOs",
            "fs.protected_fifos", "2", "0",
            "Empeche l'ouverture de FIFOs appartenant a un autre utilisateur dans"
            " un sticky directory (/tmp). Bloque les race conditions via pipes nommes."
        },
        {
            "Protection fichiers reguliers",
            "fs.protected_regular", "2", "0",
            "Meme protection que FIFOs mais pour les fichiers reguliers dans sticky"
            " dirs. Bloque les attaques TOCTOU sur les fichiers ordinaires."
        },
    };
}

std::vector<SysctlOption> KernelSecurity::netOptions() {
    return {
        {
            "Anti-spoofing IP (strict)",
            "net.ipv4.conf.all.rp_filter", "1", "0",
            "[!] CASSE : routage asymetrique, VPN, bridges Docker/libvirt."
            " Reverse Path Filtering strict : verifie que les paquets entrants"
            " arrivent par la bonne interface. Bloque l'usurpation d'adresse IP,"
            " mais rejette aussi le trafic legitime multi-chemins."
        },
        {
            "Bloquer redirections ICMP (IPv4)",
            "net.ipv4.conf.all.accept_redirects", "0", "1",
            "Refuse les redirections ICMP. Un attaquant reseau pourrait envoyer de"
            " faux messages ICMP pour rediriger le trafic vers lui (man-in-the-middle)."
        },
        {
            "Bloquer envoi redirections",
            "net.ipv4.conf.all.send_redirects", "0", "1",
            "Empeche la machine d'envoyer des redirections ICMP. Evite d'etre utilisee"
            " involontairement comme relais dans une attaque reseau."
        },
        {
            "Protection SYN flood",
            "net.ipv4.tcp_syncookies", "1", "0",
            "Active les SYN cookies. Protege contre les attaques SYN flood qui saturent"
            " la table de connexions TCP en envoyant des milliers de SYN sans reponse."
        },
        {
            "Logger paquets suspects",
            "net.ipv4.conf.all.log_martians", "1", "0",
            "Logue les paquets avec des adresses sources impossibles (adresses privees"
            " venant de l'exterieur). Permet de detecter du spoofing d'adresse IP."
        },
        {
            "Bloquer redirections ICMP (IPv6)",
            "net.ipv6.conf.all.accept_redirects", "0", "1",
            "Meme protection que IPv4 mais pour le trafic IPv6. Refuse les redirections"
            " ICMP pouvant etre utilisees pour des attaques man-in-the-middle."
        },
        {
            "Ignorer broadcast ping",
            "net.ipv4.icmp_echo_ignore_broadcasts", "1", "0",
            "Ignore les pings envoyes en broadcast. Empeche la machine d'etre utilisee"
            " comme amplificateur dans une attaque DDoS de type Smurf."
        },
        {
            "Desactiver IPv6 (si inutilise)",
            "net.ipv6.conf.all.disable_ipv6", "1", "0",
            "[!] CASSE : tout reseau IPv6, y compris certains FAI et VPN."
            " Desactive IPv6 sur toutes les interfaces. Reduit la surface"
            " d'attaque en eliminant une famille entiere de protocoles reseau."
        },
        {
            "Desactiver IP forwarding",
            "net.ipv4.ip_forward", "0", "1",
            "[!] CASSE : reseau des conteneurs Docker/Podman, machines virtuelles,"
            " partage de connexion. Empeche la machine de router des paquets entre"
            " interfaces. A n'activer que si elle n'est ni routeur ni passerelle VPN."
        },
        {
            "Protection TIME_WAIT TCP",
            "net.ipv4.tcp_rfc1337", "1", "0",
            "Protege contre le TIME_WAIT assassination. Un attaquant peut envoyer un"
            " RST pour forcer la fermeture de connexions TCP actives (RFC 1337)."
        },
        {
            "Ignorer erreurs ICMP invalides",
            "net.ipv4.icmp_ignore_bogus_error_responses", "1", "0",
            "Ignore les reponses d'erreur ICMP non conformes a la RFC 1122. Reduit"
            " le spam logs et les attaques par erreur ICMP synthetique."
        },
        {
            "Desactiver timestamps TCP",
            "net.ipv4.tcp_timestamps", "0", "1",
            "Desactive les timestamps TCP qui exposent l'uptime du systeme et"
            " facilitent certaines attaques off-path et de fingerprinting reseau."
        },
    };
}
