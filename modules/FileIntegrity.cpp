#include "FileIntegrity.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <array>
#include <sys/stat.h>
#include <unistd.h>

const std::string FileIntegrity::BASELINE_PATH = "/var/lib/spp/integrity.db";
const std::string FileIntegrity::SIG_PATH      = "/var/lib/spp/integrity.db.sig";
const std::string FileIntegrity::SERVICE_FILE  = "/etc/systemd/system/spp-integrity.service";
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

// HMAC-SHA256 : lie la signature a cette machine via machine-id
static std::string hmacSha256hex(const std::string& key, const std::string& data) {
    std::string kp(64, '\0');
    size_t klen = key.size() < 64 ? key.size() : 64;
    for (size_t i = 0; i < klen; ++i) kp[i] = key[i];

    std::string k_ipad = kp, k_opad = kp;
    for (int i = 0; i < 64; ++i) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    return sha256hex(k_opad + sha256raw32(k_ipad + data));
}

static std::string machineKey() {
    std::ifstream f("/etc/machine-id");
    if (!f.is_open()) return "spp-fallback-key-00000000000000000000000000000000";
    std::string id;
    std::getline(f, id);
    while (!id.empty() && (id.back() == '\r' || id.back() == ' '))
        id.pop_back();
    return id.empty() ? "spp-fallback-key-00000000000000000000000000000000" : id;
}

std::string FileIntegrity::sha256file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";

    std::ostringstream buf;
    buf << f.rdbuf();
    return sha256hex(buf.str());
}

bool FileIntegrity::saveBaseline(const std::vector<std::pair<std::string,std::string>>& hashes) {
    mkdir("/var/lib/spp", 0700);

    std::ostringstream content;
    content << "# SPP-INTEGRITY-BASELINE\n";
    for (const auto& [path, hash] : hashes)
        content << path << ':' << hash << '\n';
    std::string data = content.str();

    std::ofstream f(BASELINE_PATH);
    if (!f.is_open()) return false;
    f << data;
    if (!f.good()) return false;
    f.close();

    // Signe le contenu avec HMAC-SHA256(machine-id) pour detecter toute falsification
    std::string sig = hmacSha256hex(machineKey(), data);
    std::ofstream sf(SIG_PATH);
    if (!sf.is_open()) return false;
    sf << sig << '\n';
    return sf.good();
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
        std::string h = sha256file(entry.path);
        if (!h.empty())
            hashes.push_back({ entry.path, h });
    }
    return saveBaseline(hashes);
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
    struct stat st;
    // Pas de baseline = pas de falsification (juste absente)
    if (stat(BASELINE_PATH.c_str(), &st) != 0) return false;
    // Baseline presente mais signature absente = falsification
    if (stat(SIG_PATH.c_str(), &st) != 0) return true;

    std::ifstream bf(BASELINE_PATH);
    if (!bf.is_open()) return true;
    std::ostringstream buf;
    buf << bf.rdbuf();
    std::string content = buf.str();

    std::ifstream sf(SIG_PATH);
    if (!sf.is_open()) return true;
    std::string stored;
    std::getline(sf, stored);

    return stored != hmacSha256hex(machineKey(), content);
}

bool FileIntegrity::isServiceEnabled() {
    struct stat st;
    return stat(WANTS_LINK.c_str(), &st) == 0;
}

bool FileIntegrity::enableService() {
    struct stat st;
    if (stat(WANTS_LINK.c_str(), &st) == 0) return true;
    return symlink(SERVICE_FILE.c_str(), WANTS_LINK.c_str()) == 0;
}

bool FileIntegrity::disableService() {
    return unlink(WANTS_LINK.c_str()) == 0;
}

bool FileIntegrity::purge() {
    disableService();
    unlink(SERVICE_FILE.c_str());
    unlink(SIG_PATH.c_str());
    unlink(BASELINE_PATH.c_str());
    rmdir("/var/lib/spp");
    return true;
}

bool FileIntegrity::installServiceFile() {
    std::ofstream f(SERVICE_FILE);
    if (!f.is_open()) return false;
    f << "[Unit]\n"
      << "Description=SPP File Integrity Check\n"
      << "After=local-fs.target\n"
      << "\n"
      << "[Service]\n"
      << "Type=oneshot\n"
      << "ExecStart=/usr/local/bin/spp --check\n"
      << "StandardOutput=journal\n"
      << "StandardError=journal\n"
      << "\n"
      << "[Install]\n"
      << "WantedBy=multi-user.target\n";
    return f.good();
}
