#include "Namespaces.hpp"
#include <fstream>
#include <string>
#include <unistd.h>
#include <cerrno>

const std::string NamespacesSecurity::SYSCTL_CONF = "/etc/sysctl.d/99-spp-ns.conf";

std::string NamespacesSecurity::procPath(const std::string& key) {
    std::string path = "/proc/sys/";
    for (char c : key)
        path += (c == '.' ? '/' : c);
    return path;
}

std::string NamespacesSecurity::readValue(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::string val;
    std::getline(f, val);
    auto end = val.find_last_not_of(" \t\r\n");
    return (end != std::string::npos) ? val.substr(0, end + 1) : "";
}

bool NamespacesSecurity::writeValue(const std::string& path, const std::string& value) {
    std::ofstream f(path);
    if (!f.is_open()) return false;
    f << value;
    return f.good();
}

bool NamespacesSecurity::apply(const NamespaceOption& opt) {
    return writeValue(procPath(opt.key), opt.hardened);
}

bool NamespacesSecurity::revert(const NamespaceOption& opt) {
    return writeValue(procPath(opt.key), opt.defaults);
}

bool NamespacesSecurity::isHardened(const NamespaceOption& opt) {
    return readValue(procPath(opt.key)) == opt.hardened;
}

bool NamespacesSecurity::writePersistenceConf(const std::vector<std::pair<std::string,std::string>>& entries) {
    if (entries.empty()) return removePersistenceConf();
    std::ofstream f(SYSCTL_CONF);
    if (!f.is_open()) return false;
    f << "# SPP - Namespaces isolation\n";
    for (const auto& [key, val] : entries)
        f << key << " = " << val << '\n';
    return f.good();
}

bool NamespacesSecurity::removePersistenceConf() {
    return unlink(SYSCTL_CONF.c_str()) == 0 || errno == ENOENT;
}

std::vector<NamespaceOption> NamespacesSecurity::options() {
    return {
        {
            "Interdire user ns non-root",
            "kernel.unprivileged_userns_clone", "0", "1",
            "Empeche les utilisateurs normaux de creer des user namespaces."
            " Vecteur majeur d'escalade de privileges (CVE-2022-0492, etc.)."
            " (Debian/Ubuntu uniquement)"
        },
        {
            "Desactiver user namespaces",
            "user.max_user_namespaces", "0", "65536",
            "Interdit completement la creation de user namespaces. Bloque Docker"
            " sans root et les outils sandbox bases sur user ns. Durcissement"
            " maximal sur serveur dedie sans conteneurs."
        },
        {
            "Desactiver net namespaces",
            "user.max_net_namespaces", "0", "65536",
            "Interdit la creation de network namespaces. Bloque l'isolation"
            " reseau par namespace, utilisee pour contourner netfilter ou"
            " creer des interfaces reseau fantomes."
        },
        {
            "Desactiver mnt namespaces",
            "user.max_mnt_namespaces", "0", "65536",
            "Interdit la creation de mount namespaces. Bloque overlayfs et"
            " bind-mount uses pour echapper a un chroot ou monter des"
            " systemes de fichiers arbitraires."
        },
        {
            "Desactiver PID namespaces",
            "user.max_pid_namespaces", "0", "65536",
            "Interdit la creation de PID namespaces. Empeche de cacher des"
            " processus dans un espace isole, technique utilisee pour"
            " dissimuler des processus malveillants au monitoring systeme."
        },
        {
            "Desactiver IPC namespaces",
            "user.max_ipc_namespaces", "0", "65536",
            "Interdit la creation d'IPC namespaces (memoire partagee,"
            " semaphores, files de messages). Reduit les vecteurs d'injection"
            " via SysV IPC dans des espaces isoles."
        },
        {
            "Desactiver UTS namespaces",
            "user.max_uts_namespaces", "0", "65536",
            "Interdit la creation d'UTS namespaces (nom d'hote). Bloque la"
            " possibilite de changer son hostname de facon isolee, technique"
            " de camouflage dans certains exploits de privilege."
        },
        {
            "Desactiver cgroup namespaces",
            "user.max_cgroup_namespaces", "0", "65536",
            "Interdit la creation de cgroup namespaces. Empeche d'isoler la"
            " vue des cgroups pour masquer l'appartenance a un cgroup de"
            " securite ou contourner des politiques de ressources."
        },
    };
}
