#include "Cleanup.hpp"
#include "Kernel.hpp"
#include "HostsBlocker.hpp"
#include "FileIntegrity.hpp"
#include "SafeFile.hpp"
#include "SSH.hpp"
#include "State.hpp"
#include "Namespaces.hpp"

#include <unistd.h>

// Regle : desinstaller SPP ne doit jamais laisser la machine plus faible qu'il
// ne l'a trouvee. On retire ce que SPP a pose, on restaure ce que SPP a change,
// et on ne touche a rien d'autre.
//
// Les boucles de revert SELinux et AppArmor ont ete supprimees : elles
// basculaient les profils en mode complain et desactivaient des booleans que
// SPP n'avait pas forcement actives.
CleanupResult Cleanup::removeAllTraces() {
    CleanupResult r;

    // Valeurs sysctl : on repose l'etat observe avant la premiere intervention.
    // Supprimer les .conf ne suffisait pas, le durcissement restait actif en
    // memoire jusqu'au redemarrage alors que l'interface annonçait le contraire.
    for (const auto& [key, value] : SppState::all()) {
        std::string path = "/proc/sys/";
        for (char c : key) path += (c == '.' ? '/' : c);
        if (!SafeFile::exists(path)) continue;
        SafeFile::writeProc(path, value) ? ++r.ok : ++r.fail;
    }

    KernelSecurity::removePersistenceConf()     ? ++r.ok : ++r.fail;
    NamespacesSecurity::removePersistenceConf() ? ++r.ok : ++r.fail;
    HostsBlocker::apply(HostsBlocker::NONE)     ? ++r.ok : ++r.fail;
    FileIntegrity::purge()                      ? ++r.ok : ++r.fail;
    SSHSecurity::revert()                       ? ++r.ok : ++r.fail;
    SppState::purge()                           ? ++r.ok : ++r.fail;

    ::rmdir("/var/lib/spp");  // vide a ce stade ; sans consequence sinon
    return r;
}
