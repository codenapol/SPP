# Documentation des modules

## Principe directeur

> SPP ne modifie que ce que l'utilisateur a explicitement changé, restaure l'état
> **réellement observé** avant sa première intervention, et ne laisse jamais la
> machine plus faible qu'il ne l'a trouvée.

Trois mécanismes transverses appliquent cette règle :

| Mécanisme | Où | Rôle |
|---|---|---|
| Écriture atomique | `modules/SafeFile` | Aucun fichier système ne peut être détruit par une coupure |
| Mémoire de l'état d'origine | `modules/State` | La restauration repose sur ce qui a été mesuré, jamais sur une table codée en dur |
| Suivi des modifications | `Group<>` dans `main.cpp` | Une option non touchée n'est jamais réécrite |

---

## SafeFile (`modules/SafeFile`)

Primitives d'I/O sûres, utilisées par tous les autres modules.

- `writeAtomic(path, contenu, mode)` — fichier temporaire → `fchmod`/`fchown` → `fsync` → `rename()` → `fsync` du répertoire. Résout les liens symboliques pour ne pas les remplacer par un fichier ordinaire. `mode = 0` conserve les permissions existantes.
- `writeProc(path, valeur)` — `open`/`write`/`close` avec remontée d'`errno`. **Indispensable pour `/proc` et `/sys`** : un `ofstream` bufferise, si bien que `f << v; return f.good();` renvoyait `true` avant même que le noyau ait vu l'octet.
- `backupOnce(path)` / `restoreBackup(path)` — sauvegarde `path.spp-backup`, jamais écrasée.
- `trim`, `read`, `readLine`, `exists`.

---

## SppState (`modules/State`)

Fichier `/var/lib/spp/original.state`, mode **0600**.

Enregistre la valeur d'une clé **une seule fois**, juste avant la toute première écriture de SPP dessus. C'est cette valeur, et non la colonne `defaults` des tables d'options, qui fait foi pour toute restauration.

Raison d'être : la colonne `defaults` était fabriquée et fausse. Mesuré sur une Kali à jour — `fs.suid_dumpable` vaut 0 et non 1, `net.ipv4.tcp_syncookies` vaut 1 et non 0, `kernel.perf_event_paranoid` vaut 3 et non 1. Restaurer depuis cette table **dégradait** la machine.

`revert()` sans original enregistré est un **no-op délibéré** : SPP n'a jamais touché cette clé, il n'a donc rien à y défaire.

---

## KernelSecurity (`modules/Kernel`)

Durcissement via `sysctl`. Chaque option est un `SysctlOption` : `name`, `key`, `hardened`, `defaults` (dernier recours), `detail`.

**Catégories** — `kernelOptions()` (ASLR, ptrace, kptr_restrict, BPF, perf), `fsOptions()` (protections hardlink/symlink/FIFO, dumps SUID), `netOptions()` (SYN cookies, redirections ICMP, rp_filter, IPv6).

**Fan-out des clés `net.*.conf.all.*`** — une valeur écrite dans `conf/all/` n'atteint pas les interfaces déjà configurées. `apply`, `revert` et `isHardened` traitent donc aussi `conf/default/` et **chaque interface présente**. Sans cela, « Désactiver IPv6 » ne désactivait pas IPv6 sur `eth0`, et `rp_filter` pouvait s'afficher comme durci alors que l'effectif — `max(all, iface)` — ne l'était pas.

**`available(opts)`** — écarte les clés absentes du noyau courant (`kernel.yama.*` sans le LSM Yama, patchs Debian manquants). Elles disparaissent de l'interface au lieu de produire des échecs.

**Persistance** — `writeConf(path, en-tête, entrées)`, partagé avec `NamespacesSecurity`, régénère `/etc/sysctl.d/99-spp.conf` avec les options actives.

**Convention `[!]`** — un `detail` commençant par `[!]` marque une option qui casse des usages courants ; l'interface l'affiche en rouge. Concerne `rp_filter` strict, `disable_ipv6`, `ip_forward` et les namespaces.

---

## NamespacesSecurity (`modules/Namespaces`)

`NamespaceOption` est un alias de `SysctlOption` et toutes les opérations délèguent à `KernelSecurity` : le module n'était qu'un copier-coller intégral de `Kernel.cpp`. Il ne conserve que la liste d'options et son fichier de persistance `/etc/sysctl.d/99-spp-ns.conf`.

Les sept options `user.max_*_namespaces` portent le marqueur `[!]` : les mettre à 0 casse le sandbox de Chrome et Firefox, Flatpak, Docker rootless et les unités systemd en `PrivateUsers`/`ProtectSystem`.

---

## DNSSecurity (`modules/DNS`)

Interface avec `systemd-resolved` via `/etc/systemd/resolved.conf`.

- `isAvailable()` — faux si `resolved.conf` est absent ou l'unité inconnue de systemd. **La section est alors masquée** ; auparavant, chaque application comptait deux échecs pour un module qui ne pouvait rien faire.
- `applyDNSSEC(bool)`, `applyDNSOverTLS(bool)` — écriture atomique, sauvegarde préalable, section `[Resolve]` créée si absente.
- Tolère `DNSSEC = yes` (espaces) et `[Resolve]` suivi d'espaces.
- **Recharge `systemd-resolved`** après modification. Sans cela le changement n'avait aucun effet avant le redémarrage suivant.

---

## FileIntegrity (`modules/FileIntegrity`)

Baseline SHA-256 signée, pour les fichiers système critiques.

**Flux :**
1. `generateBaseline()` → hashes dans `/var/lib/spp/integrity.db` (**0600**), signature HMAC-SHA256 dans `integrity.db.sig` (**0600**).
2. `check()` → compare, retourne `OK` / `MODIFIED` / `MISSING` / `NO_BASELINE`.
3. `isBaselineTampered()` → vérifie la signature.
4. `installServiceFile()` + `enableService()` → unité systemd **et timer horaire**.

**Clé de signature** — 32 octets de `/dev/urandom` dans `/var/lib/spp/hmac.key`, mode **0600**. L'ancienne clé était `/etc/machine-id`, en **0444** : n'importe quel utilisateur pouvait recalculer une signature valide après avoir maquillé la baseline. La signature n'authentifiait rien. Root reste capable de forger une baseline — c'est inhérent à toute vérification d'intégrité locale.

**Un fichier présent mais illisible fait échouer la génération** au lieu d'être omis en silence, ce qui laissait `/etc/shadow` hors de la surveillance sans un mot.

**Timer** — un `Type=oneshot` accroché à `multi-user.target` ne s'exécute qu'une fois, au démarrage. Le timer (`OnBootSec=2min`, `OnUnitActiveSec=1h`, `Persistent=true`) en fait une véritable surveillance. `ExecStart` utilise le chemin réel du binaire (`/proc/self/exe`), et non un `/usr/local/bin/spp` codé en dur.

---

## HostsBlocker (`modules/HostsBlocker`)

Modifie `/etc/hosts` pour bloquer des domaines de tracking, entre marqueurs.

| Niveau | Domaines |
|--------|----------|
| `NONE` | 0 — restaure l'état original |
| `MINIMUM` | 19 |
| `BASIQUE` | 78 |
| `HARD` | 156 |

Écriture atomique et sauvegarde préalable : c'est le fichier le plus exposé, une coupure en pleine troncature couperait la machine de `localhost`. Un marqueur d'ouverture sans fermeture fait **abandonner** l'opération au lieu d'avaler la fin du fichier.

`t.co` est en `HARD` et non en `BASIQUE` : le bloquer casse tous les liens Twitter/X, y compris hors navigateur.

---

## Optimization (`modules/Optimization`)

Fournit des `SysctlOption` traités par `KernelSecurity`.

- `memoryOptions()` — `vm.vfs_cache_pressure`, `vm.dirty_writeback_centisecs`
- `networkOptions()` — `tcp_keepalive_time`, `net.core.rmem_max`/`wmem_max`, `netdev_max_backlog`, `somaxconn`

---

## SSHSecurity (`modules/SSH`)

**Écrit un drop-in `/etc/ssh/sshd_config.d/99-spp.conf`**, sans toucher au fichier de la distribution. OpenSSH retient la première valeur rencontrée et la directive `Include` figure en tête du `sshd_config` Debian/Ubuntu : le drop-in prime donc. Repli sur le fichier principal, avec sauvegarde, si aucun `Include` n'est présent.

- `isInstalled()` — section masquée sans serveur SSH.
- `applyDisableRootLogin(bool)` — écrire → **`sshd -t`** → rollback si invalide → recharger. Le rechargement immédiat sans validation garantissait un lock-out sur machine distante.
- Ne recharge que si le service tourne : un `ssh.service` à l'arrêt comptait un échec à chaque application.
- `revert()` — **supprime le drop-in**. N'écrit jamais `PermitRootLogin yes` : désinstaller SPP ne doit pas ouvrir un accès root qui était fermé.

---

## SELinuxSecurity (`modules/SELinux`)

Disponible si `/etc/selinux/config` est lisible.

- `modeOptions()` — bascule `enforcing` / `permissive` (`setenforce` + persistance atomique dans `/etc/selinux/config`)
- `booleanOptions()` — `allow_execstack`, `allow_execmem`, `secure_mode_insmod`, `secure_mode_policyload`, `deny_ptrace`
- `available(opts)` — écarte les booleans absents de `/sys/fs/selinux/booleans/`, sur lesquels `setsebool` échouerait

---

## AppArmorSecurity (`modules/AppArmor`)

Disponible si `/sys/module/apparmor/parameters/enabled` vaut `Y`.

- `enforcementOptions()` — bascule tous les profils en `enforce`. La commande utilise `find -maxdepth 1 -type f` : le glob `/etc/apparmor.d/*` remontait aussi `abstractions/`, `tunables/` et `local/`, si bien que `aa-enforce` **échouait systématiquement**.
- `profileOptions()` — profils individuels
- `available(opts)` — écarte les profils absents de `/etc/apparmor.d/`. Sur une Kali standard, 1 des 9 profils listés est réellement installé : les 8 autres produisaient un échec à chaque application.

---

## Cleanup (`modules/Cleanup`)

Retire ce que SPP a posé, restaure ce que SPP a changé, **et ne touche à rien d'autre**.

1. Réécrit chaque valeur sysctl mémorisée par `SppState` — supprimer les `.conf` ne suffisait pas, le durcissement restait actif en mémoire jusqu'au redémarrage
2. Supprime `/etc/sysctl.d/99-spp.conf` et `99-spp-ns.conf`
3. `HostsBlocker::apply(NONE)`
4. `FileIntegrity::purge()` — baseline, signature, clé, unité et timer
5. `SSHSecurity::revert()` — retrait du drop-in
6. `SppState::purge()`

**Ne touche ni à SELinux ni à AppArmor.** Les boucles de `revert` précédentes basculaient les profils en mode `complain` et désactivaient des booleans que SPP n'avait pas forcément activés : désinstaller l'outil affaiblissait la machine.

Retourne un rapport `{ok, fail}`.
