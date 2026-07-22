#include "Namespaces.hpp"

#include <cerrno>
#include <unistd.h>

const std::string NamespacesSecurity::SYSCTL_CONF = "/etc/sysctl.d/99-spp-ns.conf";

bool NamespacesSecurity::removePersistenceConf() {
    return ::unlink(SYSCTL_CONF.c_str()) == 0 || errno == ENOENT;
}

// Le prefixe "[!]" est reconnu par l'interface, qui affiche le detail en rouge.
// Ces options coupent des fonctionnalites que l'utilisateur utilise sans le
// savoir : elles ne doivent jamais passer pour des cases anodines.
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
            "[!] CASSE : sandbox Chrome et Firefox, Flatpak, Docker rootless,"
            " services systemd en PrivateUsers. Interdit toute creation de user"
            " namespace. A reserver a un serveur dedie sans conteneurs."
        },
        {
            "Desactiver net namespaces",
            "user.max_net_namespaces", "0", "65536",
            "[!] CASSE : Docker, Podman, VPN par namespace, systemd PrivateNetwork."
            " Interdit l'isolation reseau par namespace, utilisee pour contourner"
            " netfilter ou creer des interfaces reseau fantomes."
        },
        {
            "Desactiver mnt namespaces",
            "user.max_mnt_namespaces", "0", "65536",
            "[!] CASSE : systemd-nspawn, unites en ProtectSystem/PrivateTmp,"
            " snap et overlayfs. Bloque les bind-mounts utilises pour echapper a"
            " un chroot ou monter des systemes de fichiers arbitraires."
        },
        {
            "Desactiver PID namespaces",
            "user.max_pid_namespaces", "0", "65536",
            "[!] CASSE : tout moteur de conteneurs. Empeche de cacher des"
            " processus dans un espace isole, technique utilisee pour dissimuler"
            " des processus malveillants au monitoring systeme."
        },
        {
            "Desactiver IPC namespaces",
            "user.max_ipc_namespaces", "0", "65536",
            "[!] CASSE : conteneurs et unites systemd en PrivateIPC."
            " Interdit les IPC namespaces (memoire partagee, semaphores, files"
            " de messages) et reduit les vecteurs d'injection via SysV IPC."
        },
        {
            "Desactiver UTS namespaces",
            "user.max_uts_namespaces", "0", "65536",
            "[!] CASSE : conteneurs a hostname propre. Bloque la possibilite de"
            " changer son nom d'hote de facon isolee, technique de camouflage"
            " dans certains exploits de privilege."
        },
        {
            "Desactiver cgroup namespaces",
            "user.max_cgroup_namespaces", "0", "65536",
            "[!] CASSE : Docker, Podman, systemd en delegation de cgroups."
            " Empeche d'isoler la vue des cgroups pour masquer l'appartenance a"
            " un cgroup de securite ou contourner des politiques de ressources."
        },
    };
}
