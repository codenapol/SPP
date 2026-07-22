# Installation de SPP

## Dépendances

### FTXUI

SPP utilise [FTXUI](https://github.com/ArthurSonzogni/FTXUI) pour son interface TUI.

**Depuis les paquets (si disponible) :**
```bash
sudo apt install libftxui-dev
```

**Depuis les sources :**
```bash
git clone https://github.com/ArthurSonzogni/FTXUI.git
cd FTXUI
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --install build
```

### Outils de compilation

```bash
sudo apt install g++ cmake build-essential
```

## Compilation de SPP

```bash
git clone https://github.com/codenapol/SPP.git
cd SPP

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Le binaire est produit dans `build/spp`. La compilation en `Release` active
`-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong`, PIE et RELRO complet : un
outil de durcissement qui tourne en root doit lui-même être durci.

```bash
checksec --file=build/spp    # verification facultative
```

## Installation système (recommandé)

```bash
sudo cmake --install build --prefix /usr/local
```

Le contrôle d'intégrité périodique référence le binaire par son chemin réel.
Installer SPP à demeure avant d'activer ce contrôle évite une unité systemd
pointant vers un répertoire de compilation.

## Utilisation

SPP **exige les droits root** : sans eux l'interface afficherait un état faux,
toutes les lectures de `/etc` échouant.

```bash
sudo spp            # interface de durcissement
sudo spp --check    # controle d'integrite
sudo spp --help
```

Codes de sortie de `--check` :

| Code | Signification |
|------|---------------|
| 0 | Aucune anomalie (ou aucune baseline définie) |
| 1 | Fichier modifié ou absent |
| 2 | **Baseline falsifiée** — résultats non fiables |
| 3 | Erreur d'usage (droits insuffisants, option inconnue) |

## Désinstallation

Depuis l'interface, le bouton **Supprimer SPP** (une confirmation est demandée) :

- Restaure chaque valeur sysctl telle qu'elle était avant la première intervention
- Supprime `/etc/sysctl.d/99-spp.conf` et `99-spp-ns.conf`
- Restaure `/etc/hosts`
- Retire le drop-in `/etc/ssh/sshd_config.d/99-spp.conf`
- Supprime la baseline, sa clé, l'unité et le timer (`/var/lib/spp/`)

Il **ne touche ni à SELinux ni à AppArmor** : désinstaller SPP ne doit pas
désactiver un confinement que SPP n'a pas mis en place.

```bash
sudo rm /usr/local/bin/spp     # retrait du binaire
```
