# Documentation des modules

## KernelSecurity (`modules/Kernel`)

Gère le durcissement via `sysctl`. Chaque option est un `SysctlOption` avec :
- `name` : label affiché
- `key` : clé sysctl (ex: `kernel.randomize_va_space`)
- `hardened` / `defaults` : valeurs durcie et par défaut

**Catégories exposées :**
- `kernelOptions()`  protection mémoire noyau (ASLR, ptrace, kptr_restrict…)
- `fsOptions()`  désactivation de systèmes de fichiers inutilisés
- `netOptions()`  filtrage réseau (SYN cookies, ICMP, source routing)

**Persistance** : `writePersistenceConf()` régénère `/etc/sysctl.d/99-spp.conf` avec uniquement les options actives.

---

## DNSSecurity (`modules/DNS`)

Interface avec `systemd-resolved` via `/etc/systemd/resolved.conf`.

- `applyDNSSEC(bool)`  active/désactive `DNSSEC=yes`
- `applyDNSOverTLS(bool)`  active/désactive `DNSOverTLS=yes`

Relance automatiquement `systemd-resolved` après modification.

---

## FileIntegrity (`modules/FileIntegrity`)

Baseline SHA-256 pour les fichiers système critiques.

**Flux :**
1. `generateBaseline()` → calcule et stocke les hashes dans `/var/lib/spp/baseline.sha256`
2. `check()` → compare les hashes actuels à la baseline, retourne les résultats
3. `installServiceFile()` + `enableService()` → installe un service systemd qui exécute `spp --check` au démarrage

**Statuts possibles :** `OK`, `MODIFIED`, `MISSING`, `NO_BASELINE`

---

## HostsBlocker (`modules/HostsBlocker`)

Modifie `/etc/hosts` pour bloquer des domaines de tracking.

**Niveaux :**
| Niveau | Domaines |
|--------|----------|
| `NONE` | 0 — restaure l'état original |
| `MINIMUM` | 19 |
| `BASIQUE` | 79 |
| `HARD` | 156 |

Les entrées SPP sont encadrées par des marqueurs pour ne pas polluer le fichier original. Un `apply(NONE)` supprime proprement les marqueurs.

---

## Optimization (`modules/Optimization`)

Hérite de l'infrastructure `SysctlOption` du module Kernel.

- `memoryOptions()`  `vm.swappiness`, dirty ratios, huge pages
- `networkOptions()`  BBR congestion control, buffers TCP, `net.core.somaxconn`

---

## SSHSecurity (`modules/SSH`)

Modifie `/etc/ssh/sshd_config`.

- `applyDisableRootLogin(bool)` — ajoute ou supprime `PermitRootLogin no`
- Relance `sshd` via `systemctl restart sshd`

---

## SELinuxSecurity (`modules/SELinux`)

Disponible uniquement si SELinux est installé (`isInstalled()` vérifie la présence des binaires).

- `modeOptions()` — basculer en mode `enforcing`
- `booleanOptions()` — booleans SELinux courants (ex: `httpd_can_network_connect`)
- Applique via `/proc/sys/fs/selinux/` et `setsebool`

---

## AppArmorSecurity (`modules/AppArmor`)

Disponible uniquement si AppArmor est installé.

- `enforcementOptions()` — activer `enforce_all`
- `profileOptions()` — passer des profils individuels en mode `enforce`
- Lit/écrit dans `/sys/kernel/security/apparmor/` et les fichiers de profils

---

## Cleanup (`modules/Cleanup`)

Supprime toutes les traces SPP du système :

1. Supprime `/etc/sysctl.d/99-spp.conf`
2. Désactive et supprime le service systemd
3. Supprime la baseline `/var/lib/spp/`
4. Restaure `/etc/hosts`
5. Restaure `sshd_config`
6. Recharge sysctl

Retourne un rapport `{ok, fail}` du nombre d'opérations réussies/échouées.
