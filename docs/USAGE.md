# Guide d'utilisation

## Lancement

```bash
sudo spp
```

`sudo` est **obligatoire**. Sans lui SPP refuse de démarrer : toutes les lectures
de `/etc` échoueraient et l'interface afficherait un état faux — tout paraîtrait
non durci alors que rien ne le serait.

## Navigation

| Touche | Action |
|--------|--------|
| `↑` / `↓` | Naviguer dans les options |
| `Espace` | Cocher / décocher une option |
| `Tab` | Passer au panneau suivant |
| `Entrée` | Activer un bouton |
| Bouton Quitter | Quitter SPP |

## Ce que fait [ Appliquer ]

SPP n'agit **que sur ce que vous avez changé** depuis l'ouverture. Une case que
vous n'avez pas touchée n'est jamais réécrite : ouvrir SPP, ne rien modifier et
cliquer sur Appliquer ne change strictement rien au système et affiche
« Aucun changement à appliquer ».

Après application, l'interface relit l'état réel du système. **Une case qui se
recoche toute seule signale que l'opération n'a pas abouti** profil AppArmor
absent, boolean SELinux inconnu de la politique, etc.

Décocher une option que SPP n'a jamais activée ne fait rien non plus : le réglage
était déjà en place avant SPP, ce n'est donc pas à lui de le défaire.

## Panneau gauche — Options de sécurité

Chaque option affiche son nom et une description de son effet.

> ⚠ **Les descriptions commençant par `[!]` s'affichent en rouge.** Elles
> signalent une option qui casse des usages courants : sandbox des navigateurs,
> Docker, VPN, IPv6. Ne les cochez qu'en connaissance de cause.

Les sections dont aucune option n'est applicable sur votre machine **ne
s'affichent pas** : module absent, clé sysctl inexistante sur votre noyau,
profil AppArmor non installé.

## Panneau droit : Trackers & Intégrité

### Bloqueur de trackers

| Niveau | Domaines | Effet |
|--------|----------|-------|
| Aucune | 0 | `/etc/hosts` non modifié |
| Minimum | 19 | Trackers publicitaires majeurs, aucun faux positif |
| Basique | 78 | Couverture étendue, sites normalement fonctionnels |
| Hard | 156 | Agressif — casse les liens `t.co`, les chats live et la remontée d'erreurs |

Le contenu original de `/etc/hosts` est préservé entre les marqueurs
`# SPP-TRACKER-BEGIN` / `# SPP-TRACKER-END`, et une sauvegarde
`/etc/hosts.spp-backup` est créée à la première modification.

### Intégrité des fichiers

1. **[ Créer baseline ]** enregistre les empreintes SHA-256 des fichiers critiques
   dans `/var/lib/spp/`, signées avec une clé aléatoire lisible du seul root.
2. **[ Vérifier ]** compare l'état actuel à la baseline.
3. Cochez **Vérification horaire au démarrage** pour installer un timer systemd.

Fichiers surveillés : `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`,
`/etc/hosts`, `/etc/fstab`, `/etc/crontab`, `/etc/ssh/sshd_config`.

Installez SPP à demeure (`sudo cmake --install build --prefix /usr/local`) avant
d'activer le contrôle périodique : l'unité systemd référence le chemin réel du
binaire.

## Mode non-interactif (--check)

```bash
sudo spp --check
```

| Code | Signification |
|------|---------------|
| 0 | Aucune anomalie, ou aucune baseline définie |
| 1 | Fichier modifié ou absent |
| 2 | **Baseline falsifiée** — les résultats ne veulent rien dire |
| 3 | Erreur d'usage (droits insuffisants, option inconnue) |

Les alertes sont journalisées via syslog en `authpriv` (`journalctl -t spp-integrity`).

## Journal d'audit

Chaque changement appliqué est journalisé :

```bash
journalctl -t spp
```

## Persistance

| Élément | Emplacement |
|---|---|
| Réglages sysctl | `/etc/sysctl.d/99-spp.conf` |
| Namespaces | `/etc/sysctl.d/99-spp-ns.conf` |
| Blocage root SSH | `/etc/ssh/sshd_config.d/99-spp.conf` |
| État d'origine du système | `/var/lib/spp/original.state` (0600) |
| Baseline, signature, clé | `/var/lib/spp/` (0600) |

`original.state` mémorise chaque valeur telle qu'elle était **avant** la première
intervention de SPP. C'est ce fichier qui permet à **[ Supprimer SPP ]** de
restaurer exactement l'état d'origine. Ne le supprimez pas manuellement.
