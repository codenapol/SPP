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

## Installation système (optionnel)

Pour rendre `spp` accessible depuis n'importe où :

```bash
sudo cp spp /usr/local/bin/spp
sudo chmod 755 /usr/local/bin/spp
```

## Vérification

```bash
./spp --check
# Doit retourner 0 (pas d'anomalie) si aucune baseline n'est définie
```

## Désinstallation

Depuis l'interface SPP, utilisez le bouton **Supprimer SPP** qui :
- Supprime la configuration sysctl persistante (`/etc/sysctl.d/99-spp.conf`)
- Désactive et supprime le service systemd d'intégrité
- Restaure `/etc/hosts` à son état d'origine
- Restaure `sshd_config`
- Supprime la baseline (`/var/lib/spp/`)
