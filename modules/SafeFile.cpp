#include "SafeFile.hpp"

#include <fstream>
#include <sstream>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace SafeFile {

const std::string BACKUP_SUFFIX = ".spp-backup";

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

bool exists(const std::string& path) {
    struct stat st;
    return ::stat(path.c_str(), &st) == 0;
}

std::string read(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";
    std::ostringstream buf;
    buf << f.rdbuf();
    return buf.str();
}

std::string readLine(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::string line;
    std::getline(f, line);
    return trim(line);
}

// ─── interne ──────────────────────────────────────────────────────────────────

static std::string dirOf(const std::string& path) {
    auto pos = path.find_last_of('/');
    if (pos == std::string::npos) return ".";
    return path.substr(0, pos ? pos : 1);
}

// Si la cible est un lien symbolique, on ecrit le fichier pointe : un rename()
// sur le lien le remplacerait par un fichier ordinaire.
static std::string resolveTarget(const std::string& path) {
    char buf[PATH_MAX];
    if (::realpath(path.c_str(), buf)) return std::string(buf);
    return path;  // fichier encore inexistant
}

static void fsyncDir(const std::string& dir) {
    int fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return;
    ::fsync(fd);
    ::close(fd);
}

static bool writeAll(int fd, const std::string& data) {
    const char* p = data.data();
    size_t left = data.size();
    while (left > 0) {
        ssize_t n = ::write(fd, p, left);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        p += n;
        left -= static_cast<size_t>(n);
    }
    return true;
}

// ─── ecriture atomique ────────────────────────────────────────────────────────

bool writeAtomic(const std::string& path, const std::string& content, mode_t mode) {
    const std::string target = resolveTarget(path);

    struct stat st;
    const bool existed = (::stat(target.c_str(), &st) == 0);
    if (mode == 0)
        mode = existed ? (st.st_mode & 07777) : 0644;

    const std::string tmp = target + ".spp-tmp";
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) return false;

    auto fail = [&] { ::close(fd); ::unlink(tmp.c_str()); return false; };

    // open() applique l'umask : on impose le mode explicitement.
    if (::fchmod(fd, mode) != 0) return fail();
    if (existed) {
        int rc = ::fchown(fd, st.st_uid, st.st_gid);  // best-effort
        (void)rc;
    }

    if (!writeAll(fd, content)) return fail();

    // Les donnees doivent etre sur disque AVANT le rename, sinon un crash
    // laisse un fichier vide a la place de l'original.
    if (::fsync(fd) != 0) return fail();
    if (::close(fd) != 0) { ::unlink(tmp.c_str()); return false; }

    if (::rename(tmp.c_str(), target.c_str()) != 0) {
        ::unlink(tmp.c_str());
        return false;
    }

    fsyncDir(dirOf(target));  // rend le rename durable ; best-effort
    return true;
}

bool writeProc(const std::string& path, const std::string& value) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t n = ::write(fd, value.data(), value.size());
    bool ok = (n == static_cast<ssize_t>(value.size()));
    if (::close(fd) != 0) ok = false;  // le noyau peut refuser la valeur ici
    return ok;
}

// ─── sauvegardes ──────────────────────────────────────────────────────────────

bool backupOnce(const std::string& path) {
    const std::string bak = path + BACKUP_SUFFIX;
    if (exists(bak))  return true;  // deja sauvegarde : ne jamais ecraser l'original
    if (!exists(path)) return true;  // rien a sauvegarder

    struct stat st;
    if (::stat(path.c_str(), &st) != 0) return false;
    return writeAtomic(bak, read(path), st.st_mode & 07777);
}

bool restoreBackup(const std::string& path) {
    const std::string bak = path + BACKUP_SUFFIX;
    if (!exists(bak)) return false;

    struct stat st;
    mode_t mode = (::stat(bak.c_str(), &st) == 0) ? (st.st_mode & 07777) : 0644;
    if (!writeAtomic(path, read(bak), mode)) return false;

    ::unlink(bak.c_str());
    return true;
}

}  // namespace SafeFile
