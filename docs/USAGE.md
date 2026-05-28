# Guide d'utilisation

## Lancement

```bash
sudo ./spp
```

`sudo` est nécessaire pour appliquer les changements système. L'interface peut être ouverte sans `sudo` pour consulter l'état actuel, mais le bouton **Appliquer** échouera.

## Navigation

| Touche | Action |
|--------|--------|
| `↑` / `↓` | Naviguer dans les options |
| `Espace` | Cocher / décocher une option |
| `Tab` | Passer au panneau suivant |
| `Entrée` | Activer un bouton |
| `q` ou bouton Quitter | Quitter SPP |

## Workflow typique

1. **Cocher** les options de sécurité souhaitées dans le panneau gauche
2. **Sélectionner** un niveau de blocage de trackers (panneau droit)
3. **Configurer** l'intégrité de fichiers si nécessaire
4. Cliquer **[ Appliquer ]** pour activer tous les changements

## Panneau gauche Options de sécurité

Chaque option affiche :
- Son nom
- Une description courte de son effet

Les options cochées seront **activées**, les décochées seront **désactivées** lors de l'application.

## Panneau droit Trackers & Intégrité

### Bloqueur de trackers

Sélectionnez un niveau :
- **Aucune** : pas de modification de `/etc/hosts`
- **Minimum** (19 domaines) : blocage des trackers publicitaires majeurs
- **Basique** (79 domaines) : couverture étendue
- **Hard** (156 domaines) : blocage agressif

Le contenu original de `/etc/hosts` est préservé grâce à des marqueurs `# SPP BEGIN` / `# SPP END`.

### Intégrité des fichiers

1. Cochez **Activer au démarrage** pour installer un service systemd
2. Cliquez **[ Créer baseline ]** pour enregistrer les hashes SHA-256 des fichiers critiques
3. Cliquez **[ Vérifier ]** pour comparer l'état actuel à la baseline

Fichiers surveillés : `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, fichiers SSH, etc.

## Mode non-interactif (--check)

```bash
sudo ./spp --check
```

- Retourne **0** si tous les fichiers sont intègres (ou si aucune baseline n'existe)
- Retourne **1** si une anomalie est détectée
- Journalise les alertes dans syslog (`/var/log/syslog`)

Utile dans un script cron ou un service systemd.

## Persistance

Les paramètres sysctl sont persistés dans `/etc/sysctl.d/99-spp.conf` et rechargés à chaque démarrage. Les autres configurations (DNS, SSH) sont écrites directement dans leurs fichiers système respectifs.
