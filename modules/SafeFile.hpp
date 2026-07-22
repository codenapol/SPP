#pragma once
#include <string>
#include <sys/types.h>

// Primitives d'ecriture sures.
//
// Deux pieges que ce module elimine :
//   1. ofstream ouvre en troncature : une coupure en cours d'ecriture detruit
//      /etc/hosts ou sshd_config. writeAtomic() passe par tmp + rename().
//   2. ofstream bufferise : `f << v; return f.good();` renvoie true avant meme
//      que le noyau ait vu l'octet. writeProc() utilise write() et lit errno.
namespace SafeFile {

std::string trim(const std::string& s);
bool        exists(const std::string& path);
std::string read(const std::string& path);      // fichier entier, "" si illisible
std::string readLine(const std::string& path);  // premiere ligne, trimee

// tmp dans le meme repertoire -> fchmod/fchown -> fsync -> rename -> fsync(dir).
// mode = 0 : conserve les permissions existantes (0644 si le fichier est nouveau).
bool writeAtomic(const std::string& path, const std::string& content, mode_t mode = 0);

// Ecriture directe pour /proc et /sys : un seul write(), erreur remontee.
bool writeProc(const std::string& path, const std::string& value);

bool backupOnce(const std::string& path);     // path.spp-backup, jamais ecrase
bool restoreBackup(const std::string& path);  // restaure puis supprime la sauvegarde

extern const std::string BACKUP_SUFFIX;

}  // namespace SafeFile
