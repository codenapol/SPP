#include "Optimization.hpp"

std::vector<SysctlOption> Optimization::memoryOptions() {
    return {
        {
            "Cache inodes actif",
            "vm.vfs_cache_pressure", "50", "100",
            "Conserve le cache inodes/dentries 2x plus longtemps en memoire."
            " Accelere les acces fichiers repetes sans lecture disque supplementaire."
        },
        {
            "Flush disque espaced",
            "vm.dirty_writeback_centisecs", "1500", "500",
            "Pdflush se reveille toutes les 15s au lieu de 5s. Reduit les micro-pauses"
            " I/O periodiques sur les systemes avec acces disque frequent."
        },
    };
}

std::vector<SysctlOption> Optimization::networkOptions() {
    return {
        {
            "Keepalive TCP 40 min",
            "net.ipv4.tcp_keepalive_time", "2400", "7200",
            "Detecte les connexions mortes en 40 min au lieu de 2h. Libere plus"
            " rapidement les ressources des connexions silencieuses abandonees."
        },
        {
            "Buffer reception 4 MB",
            "net.core.rmem_max", "4194304", "212992",
            "Augmente le buffer de reception reseau a 4 MB. Ameliore le debit sur"
            " les connexions haut debit en evitant les drops de paquets."
        },
        {
            "Buffer emission 4 MB",
            "net.core.wmem_max", "4194304", "212992",
            "Augmente le buffer d'emission reseau a 4 MB. Reduit les ralentissements"
            " d'envoi lors de transferts importants ou connexions multiples."
        },
        {
            "File paquets elargie",
            "net.core.netdev_max_backlog", "5000", "1000",
            "Agrandit la file d'attente des paquets entrants a 5000. Evite les pertes"
            " en cas de pic de trafic quand le CPU traite lentement les paquets."
        },
        {
            "Backlog sockets 8192",
            "net.core.somaxconn", "8192", "4096",
            "Double le backlog max des sockets en ecoute. Utile pour les serveurs ou"
            " applications gerant de nombreuses connexions simultanees."
        },
    };
}
