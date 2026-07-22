#include "FileIntegrity.hpp"
#include "SafeFile.hpp"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cstdlib>
#include <cerrno>
#include <climits>
#include <array>
#include <sys/stat.h>
#include <unistd.h>

const std::string FileIntegrity::BASELINE_PATH = "/var/lib/spp/integrity.db";
const std::string FileIntegrity::SIG_PATH      = "/var/lib/spp/integrity.db.sig";
const std::string FileIntegrity::KEY_PATH      = "/var/lib/spp/hmac.key";
const std::string FileIntegrity::SERVICE_FILE  = "/etc/systemd/system/spp-integrity.service";
const std::string FileIntegrity::TIMER_FILE    = "/etc/systemd/system/spp-integrity.timer";
const std::string FileIntegrity::TIMER_LINK    = "/etc/systemd/system/timers.target.wants/spp-integrity.timer";
const std::string FileIntegrity::WANTS_LINK    = "/etc/systemd/system/multi-user.target.wants/spp-integrity.service";

static const std::array<uint32_t, 64> K = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256compute(const std::string& data, uint32_t h[8]) {
    h[0]=0x6a09e667; h[1]=0xbb67ae85; h[2]=0x3c6ef372; h[3]=0xa54ff53a;
    h[4]=0x510e527f; h[5]=0x9b05688c; h[6]=0x1f83d9ab; h[7]=0x5be0cd19;

    std::string msg = data;
    uint64_t bits = (uint64_t)data.size() * 8;
    msg += '\x80';
    while (msg.size() % 64 != 56) msg += '\x00';
    for (int i = 7; i >= 0; --i)
        msg += (char)((bits >> (i * 8)) & 0xff);

    for (size_t off = 0; off < msg.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = ((uint8_t)msg[off+i*4]   << 24) | ((uint8_t)msg[off+i*4+1] << 16) |
                   ((uint8_t)msg[off+i*4+2] <<  8) |  (uint8_t)msg[off+i*4+3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>3);
            uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19)  ^ (w[i-2]>>10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1  = rotr(e,6)^rotr(e,11)^rotr(e,25);
            uint32_t ch  = (e&f)^(~e&g);
            uint32_t tmp1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0  = rotr(a,2)^rotr(a,13)^rotr(a,22);
            uint32_t maj = (a&b)^(a&c)^(b&c);
            uint32_t tmp2 = S0 + maj;
            hh=g; g=f; f=e; e=d+tmp1; d=c; c=b; b=a; a=tmp1+tmp2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
}

// Returns raw 32-byte digest (needed for HMAC inner hash)
static std::string sha256raw32(const std::string& data) {
    uint32_t h[8];
    sha256compute(data, h);
    std::string out(32, '\0');
    for (int i = 0; i < 8; ++i) {
        out[i*4+0] = (char)((h[i] >> 24) & 0xff);
        out[i*4+1] = (char)((h[i] >> 16) & 0xff);
        out[i*4+2] = (char)((h[i] >>  8) & 0xff);
        out[i*4+3] = (char)( h[i]        & 0xff);
    }
    return out;
}

static std::string sha256hex(const std::string& data) {
    uint32_t h[8];
    sha256compute(data, h);
    std::ostringstream oss;
    for (int i = 0; i < 8; ++i)
        oss << std::hex << std::setw(8) << std::setfill('0') << h[i];
    return oss.str();
}

static std::string hmacSha256hex(const std::string& key, const std::string& data) {
    // RFC 2104 : une cle plus longue qu'un bloc est hachee, jamais tronquee.
    const std::string k = (key.size() > 64) ? sha256raw32(key) : key;

    std::string kp(64, '\0');
    for (size_t i = 0; i < k.size(); ++i) kp[i] = k[i];

    std::string k_ipad = kp, k_opad = kp;
    for (int i = 0; i < 64; ++i) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    return sha256hex(k_opad + sha256raw32(k_ipad + data));
}

// Cle de signature propre a l'installation, creee a la volee et lisible du seul
// root. L'ancienne cle etait /etc/machine-id, en 0444 : n'importe quel
// utilisateur pouvait recalculer une signature valide apres avoir maquille la
// baseline. La signature n'authentifiait donc rien.
static std::string integrityKey(const std::string& keyPath) {
    const std::string existing = SafeFile::read(keyPath);
    if (existing.size() == 32) return existing;

    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom.is_open()) return "";
    std::string raw(32, '\0');
    urandom.read(&raw[0], 32);
    if (urandom.gcount() != 32) return "";

    if (::mkdir("/var/lib/spp", 0700) != 0 && errno != EEXIST) return "";
    if (!SafeFile::writeAtomic(keyPath, raw, 0600)) return "";
    return raw;
}

std::string FileIntegrity::sha256file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";

    std::ostringstream buf;
    buf << f.rdbuf();
    return sha256hex(buf.str());
}

bool FileIntegrity::saveBaseline(const std::vector<std::pair<std::string,std::string>>& hashes) {
    if (::mkdir("/var/lib/spp", 0700) != 0 && errno != EEXIST) return false;

    const std::string key = integrityKey(KEY_PATH);
    if (key.empty()) return false;  // sans cle, une baseline non signee ne vaut rien

    std::ostringstream content;
    content << "# SPP-INTEGRITY-BASELINE\n";
    for (const auto& [path, hash] : hashes)
        content << path << ':' << hash << '\n';
    const std::string data = content.str();

    // 0600 : la baseline revele quels fichiers sont surveilles.
    if (!SafeFile::writeAtomic(BASELINE_PATH, data, 0600)) return false;
    return SafeFile::writeAtomic(SIG_PATH, hmacSha256hex(key, data) + "\n", 0600);
}

std::vector<std::pair<std::string,std::string>> FileIntegrity::loadBaseline() {
    std::vector<std::pair<std::string,std::string>> result;
    std::ifstream f(BASELINE_PATH);
    if (!f.is_open()) return result;

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto sep = line.find(':');
        if (sep == std::string::npos) continue;
        result.push_back({ line.substr(0, sep), line.substr(sep + 1) });
    }
    return result;
}

std::vector<FileEntry> FileIntegrity::criticalFiles() {
    return {
        { "/etc/passwd",           "passwd",      "Comptes utilisateurs systeme"          },
        { "/etc/shadow",           "shadow",      "Mots de passe haches (root-only)"      },
        { "/etc/group",            "group",       "Groupes et appartenances"              },
        { "/etc/sudoers",          "sudoers",     "Privileges sudo accordes"              },
        { "/etc/hosts",            "hosts",       "Resolutions DNS locales"               },
        { "/etc/fstab",            "fstab",       "Points de montage systeme"             },
        { "/etc/crontab",          "crontab",     "Taches planifiees systeme"             },
        { "/etc/ssh/sshd_config",  "sshd_config", "Configuration du serveur SSH"          },
    };
}

bool FileIntegrity::generateBaseline() {
    std::vector<std::pair<std::string,std::string>> hashes;
    for (const auto& entry : criticalFiles()) {
        const std::string h = sha256file(entry.path);
        if (!h.empty()) {
            hashes.push_back({ entry.path, h });
            continue;
        }
        // Present mais illisible : l'omettre en silence laissait un trou dans la
        // surveillance -- typiquement /etc/shadow quand SPP tourne sans root.
        if (SafeFile::exists(entry.path)) return false;
        // Reellement absent de cette machine : normal, on passe.
    }
    return !hashes.empty() && saveBaseline(hashes);
}

std::vector<IntegrityResult> FileIntegrity::check() {
    auto baseline = loadBaseline();
    auto files    = criticalFiles();
    std::vector<IntegrityResult> results;

    for (const auto& entry : files) {
        IntegrityResult r;
        r.path  = entry.path;
        r.label = entry.label;

        std::string saved;
        bool found = false;
        for (const auto& [p, h] : baseline) {
            if (p == entry.path) { saved = h; found = true; break; }
        }

        if (!found) {
            r.status = IntegrityResult::NO_BASELINE;
        } else {
            struct stat st;
            if (stat(entry.path.c_str(), &st) != 0) {
                r.status = IntegrityResult::MISSING;
            } else {
                std::string current = sha256file(entry.path);
                r.status = (current == saved) ? IntegrityResult::OK : IntegrityResult::MODIFIED;
            }
        }
        results.push_back(r);
    }
    return results;
}

bool FileIntegrity::hasBaseline() {
    struct stat st;
    return stat(BASELINE_PATH.c_str(), &st) == 0;
}

bool FileIntegrity::isBaselineTampered() {
    // Pas de baseline = pas de falsification (juste absente)
    if (!SafeFile::exists(BASELINE_PATH)) return false;
    // Baseline presente mais signature ou cle absente = falsification
    if (!SafeFile::exists(SIG_PATH)) return true;
    if (!SafeFile::exists(KEY_PATH)) return true;

    const std::string key = SafeFile::read(KEY_PATH);
    if (key.size() != 32) return true;

    const std::string content = SafeFile::read(BASELINE_PATH);
    const std::string stored  = SafeFile::readLine(SIG_PATH);

    return stored != hmacSha256hex(key, content);
}

// ─── service systemd ──────────────────────────────────────────────────────────

// systemctl echoue legitimement quand l'unite n'existe pas encore ou plus :
// son code de retour n'est pas significatif pour ces appels de nettoyage.
static void runQuiet(const char* cmd) {
    int rc = std::system(cmd);
    (void)rc;
}

// Chemin reel du binaire : l'ancien "/usr/local/bin/spp" code en dur produisait
// une unite morte des que SPP tournait depuis son repertoire de compilation.
static std::string selfPath() {
    char buf[PATH_MAX];
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return "/usr/local/bin/spp";
    buf[n] = '\0';
    return std::string(buf);
}

bool FileIntegrity::isServiceEnabled() {
    return SafeFile::exists(TIMER_LINK);
}

bool FileIntegrity::enableService() {
    if (!SafeFile::exists(SERVICE_FILE) || !SafeFile::exists(TIMER_FILE))
        return false;
    // systemctl pose le lien ET recharge systemd. Le symlink cree a la main
    // laissait l'unite invisible jusqu'au redemarrage suivant.
    return std::system("systemctl enable --now spp-integrity.timer 2>/dev/null") == 0;
}

bool FileIntegrity::disableService() {
    // Echoue si l'unite n'a jamais existe : sans consequence, on nettoie ensuite.
    runQuiet("systemctl disable --now spp-integrity.timer 2>/dev/null");
    // Lien pose a la main par les versions precedentes de SPP.
    if (::unlink(WANTS_LINK.c_str()) != 0 && errno != ENOENT) return false;
    // Desactiver ce qui n'a jamais ete active n'est pas un echec.
    return true;
}

bool FileIntegrity::purge() {
    disableService();
    ::unlink(TIMER_FILE.c_str());
    ::unlink(SERVICE_FILE.c_str());
    ::unlink(SIG_PATH.c_str());
    ::unlink(BASELINE_PATH.c_str());
    ::unlink(KEY_PATH.c_str());
    runQuiet("systemctl daemon-reload 2>/dev/null");
    ::rmdir("/var/lib/spp");  // echoue tant que l'etat d'origine y reste : voulu
    return true;
}

bool FileIntegrity::installServiceFile() {
    std::ostringstream service;
    service << "[Unit]\n"
            << "Description=SPP - controle d'integrite des fichiers systeme\n"
            << "After=local-fs.target\n"
            << "\n"
            << "[Service]\n"
            << "Type=oneshot\n"
            << "ExecStart=" << selfPath() << " --check\n"
            << "StandardOutput=journal\n"
            << "StandardError=journal\n";
    if (!SafeFile::writeAtomic(SERVICE_FILE, service.str(), 0644))
        return false;

    // Sans timer, un Type=oneshot accroche a multi-user.target ne verifie
    // qu'une seule fois, au demarrage : ce n'est pas de la surveillance.
    std::ostringstream timer;
    timer << "[Unit]\n"
          << "Description=SPP - controle d'integrite periodique\n"
          << "\n"
          << "[Timer]\n"
          << "OnBootSec=2min\n"
          << "OnUnitActiveSec=1h\n"
          << "Persistent=true\n"
          << "\n"
          << "[Install]\n"
          << "WantedBy=timers.target\n";
    if (!SafeFile::writeAtomic(TIMER_FILE, timer.str(), 0644))
        return false;

    runQuiet("systemctl daemon-reload 2>/dev/null");
    return true;
}
