# SPP :

> Outil de durcissement Linux avec interface TUI interactive, conçu pour Kali Linux et les distributions Debian/Ubuntu.

![C++](https://img.shields.io/badge/C%2B%2B-17-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

## Aperçu

SPP est un outil en ligne de commande (TUI) qui centralise les opérations de durcissement de sécurité Linux. Il permet d'appliquer, de surveiller et de restaurer des configurations de sécurité depuis une interface unifiée sans avoir à jongler entre de multiples fichiers de configuration système.

```
┌─ SPP — Système de Protection Patriote ──────────────────────────────┐
│                                                                      │
│  KERNEL          │  BLOQUEUR DE TRACKERS                            │
│  ├─ [x] ASLR     │  ○ Aucune                                        │
│  ├─ [x] ...      │  ● Minimum  —  19 domaines                       │
│                  │  ○ Basique  —  79 domaines                       │
│  DNS             │  ○ Hard     — 156 domaines                       │
│  ├─ [x] DNSSEC   │                                                  │
│  └─ [x] DoT      │  INTÉGRITÉ FICHIERS                              │
│                  │  [ Créer baseline ]  [ Vérifier ]                │
│  [ Appliquer ]   [ Supprimer SPP ]   [ Quitter ]                    │
└──────────────────────────────────────────────────────────────────────┘
```

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
| **SELinux** | Mode enforcing + booleans (si SELinux installé) |
| **AppArmor** | Profils enforce (si AppArmor installé) |
| **Hosts Blocker** | Blocage de trackers via /etc/hosts (3 niveaux : 19 / 79 / 156 domaines) |
| **File Integrity** | Baseline SHA-256 + vérification + service systemd au démarrage |
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
g++ -std=c++17 -O2 \
    main.cpp \
    modules/Kernel.cpp \
    modules/DNS.cpp \
    modules/FileIntegrity.cpp \
    modules/HostsBlocker.cpp \
    modules/Optimization.cpp \
    modules/Cleanup.cpp \
    modules/SSH.cpp \
    modules/SELinux.cpp \
    modules/AppArmor.cpp \
    -lftxui-component -lftxui-dom -lftxui-screen \
    -o spp
```

Ou avec CMake si un `CMakeLists.txt` est disponible :

```bash
cmake -B build && cmake --build build
```

## Utilisation

```bash
# Interface graphique interactive
sudo ./spp

# Vérification d'intégrité en mode non-interactif (pour cron/systemd)
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
    ├── Kernel.cpp/.hpp   # Durcissement sysctl
    ├── DNS.cpp/.hpp      # DNSSEC / DNS over TLS
    ├── FileIntegrity.cpp/.hpp  # Baseline SHA-256 + service
    ├── HostsBlocker.cpp/.hpp   # Blocage trackers /etc/hosts
    ├── Optimization.cpp/.hpp   # Optimisations mémoire/réseau
    ├── Cleanup.cpp/.hpp        # Suppression des traces
    ├── SSH.cpp/.hpp            # Sécurité SSH
    ├── SELinux.cpp/.hpp        # Gestion SELinux
    └── AppArmor.cpp/.hpp       # Gestion AppArmor
```

## Avertissement

SPP modifie des paramètres système sensibles. Testez toujours dans un environnement contrôlé avant de déployer en production. Le bouton **Supprimer SPP** permet de restaurer tous les paramètres à leur valeur par défaut.

## Licence

MIT : [LICENSE](LICENSE)
