# SPP 

> Outil de durcissement Linux avec interface TUI interactive, conçu pour et sur Kali Linux mais utilisable sur les distributions Debian/Ubuntu.

![C++](https://img.shields.io/badge/C%2B%2B-17-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

## Aperçu
SPP est un outil en ligne de commande (TUI) qui centralise les opérations de
durcissement de sécurité Linux. Il permet d'appliquer, de surveiller et de
restaurer des configurations de sécurité depuis une interface unifiée, sans
avoir à jongler entre de multiples fichiers de configuration système.

Les options proposées suivent les recommandations du
[guide ANSSI de configuration Linux (v2.0)](https://messervices.cyber.gouv.fr/documents-guides/fr_np_linux_configuration-v2.0.pdf).

## Fonctionnalités

| Module | Description |
|--------|-------------|
| **Kernel** | Durcissement sysctl : ASLR, protection ptrace, kptr_restrict, dmesg_restrict |
| **Filesystem** | Désactivation des modules noyau inutiles (cramfs, freevxfs…) |
| **Réseau** | Protection SYN flood, désactivation ICMP redirect, source routing |
| **DNS** | DNSSEC + DNS over TLS via systemd-resolved |
| **Mémoire** | Optimisation vm.swappiness, paramètres huge pages |
| **Perf réseau** | BBR, paramètres TCP avancés |
| **SSH** | Désactivation du login root via SSH |
| **Namespaces** | Restriction des user namespaces non privilégiés |
| **SELinux** | Mode enforcing + booleans (si SELinux installé) |
| **AppArmor** | Profils enforce (si AppArmor installé) |
| **Hosts Blocker** | Blocage de trackers via /etc/hosts (3 niveaux : 19 / 79 / 156 domaines) |
| **File Integrity** | Baseline SHA-256 signée en HMAC-SHA256 + vérification + service systemd au démarrage |
| **Cleanup** | Suppression complète de toutes les traces SPP |

## Prérequis

- Linux (Debian, Kali, Ubuntu)
- `sudo` pour appliquer les changements système
- Dépendance de build : [FTXUI](https://github.com/ArthurSonzogni/FTXUI)

```bash
# Installer FTXUI (exemple Debian/Ubuntu)
sudo apt install libftxui-dev
# ou compiler depuis les sources : https://github.com/ArthurSonzogni/FTXUI
```

## Compilation

```bash
git clone https://github.com/codenapol/SPP.git
cd SPP
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
sudo cmake --install build   # optionnel, installe dans /usr/local/bin
```

## Utilisation

```bash
# Pour run SPP
sudo ./spp

# Vérification d'intégrité en mode non-interactif
sudo ./spp --check
# Retourne 0 si tout est OK, 1 si anomalie détectée
```

## Documentation

- [Installation détaillée](docs/INSTALL.md)
- [Guide d'utilisation](docs/USAGE.md)
- [Description des modules](docs/MODULES.md)

## Structure du projet

```
SPP/
├── main.cpp              # Point d'entrée, interface TUI (FTXUI)
└── modules/
    ├── SafeFile.cpp/.hpp       # Écriture atomique des fichiers système
    ├── State.cpp/.hpp          # Capture/restauration de l'état système
    ├── Kernel.cpp/.hpp         # Durcissement sysctl (kernel.*, fs.*, net.*)
    ├── Optimization.cpp/.hpp   # Réglages perf mémoire (vm.*) et réseau
    ├── Namespaces.cpp/.hpp     # Restriction user namespaces
    ├── DNS.cpp/.hpp            # DNSSEC / DNS over TLS
    ├── SSH.cpp/.hpp            # Sécurité SSH
    ├── SELinux.cpp/.hpp        # Gestion SELinux
    ├── AppArmor.cpp/.hpp       # Gestion AppArmor
    ├── HostsBlocker.cpp/.hpp   # Blocage trackers /etc/hosts
    ├── FileIntegrity.cpp/.hpp  # Baseline SHA-256 + service systemd
    └── Cleanup.cpp/.hpp        # Suppression des traces
```

## Avertissement

SPP modifie des paramètres système sensibles. Testez toujours dans un environnement contrôlé avant de déployer en production. Le bouton **Supprimer SPP** permet de restaurer tous les paramètres à leur valeur par défaut.

## Licence

MIT : [LICENSE](LICENSE)
