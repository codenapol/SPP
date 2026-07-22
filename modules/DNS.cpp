#include "DNS.hpp"
#include "SafeFile.hpp"

#include <sstream>
#include <vector>
#include <cstdlib>

static const std::string CONF = "/etc/systemd/resolved.conf";

// Un en-tete de section peut porter des espaces : "[Resolve] " doit compter.
static bool isSection(const std::string& line, const char* name) {
    const std::string t = SafeFile::trim(line);
    return t == name;
}

static bool isAnySection(const std::string& line) {
    const std::string t = SafeFile::trim(line);
    return !t.empty() && t[0] == '[';
}

bool DNSSecurity::isAvailable() {
    if (!SafeFile::exists(CONF)) return false;
    // "unknown" = unite inconnue de systemd ; tout le reste (active, inactive,
    // masked...) signifie que resolved existe et peut etre configure.
    return std::system("systemctl cat systemd-resolved >/dev/null 2>&1") == 0;
}

std::string DNSSecurity::readKey(const std::string& key) {
    std::istringstream in(SafeFile::read(CONF));
    std::string line;
    bool inResolve = false;

    while (std::getline(in, line)) {
        if (isSection(line, "[Resolve]")) { inResolve = true; continue; }
        if (!inResolve) continue;
        if (isAnySection(line)) break;

        const std::string t = SafeFile::trim(line);
        if (t.empty() || t[0] == '#') continue;

        const auto eq = t.find('=');
        if (eq == std::string::npos) continue;
        // Tolere "DNSSEC = yes" comme "DNSSEC=yes".
        if (SafeFile::trim(t.substr(0, eq)) == key)
            return SafeFile::trim(t.substr(eq + 1));
    }
    return "";
}

bool DNSSecurity::writeKey(const std::string& key, const std::string& value) {
    if (!SafeFile::exists(CONF)) return false;
    SafeFile::backupOnce(CONF);

    std::vector<std::string> lines;
    {
        std::istringstream in(SafeFile::read(CONF));
        std::string line;
        while (std::getline(in, line)) lines.push_back(line);
    }

    const std::string entry = key + "=" + value;
    bool inResolve = false;
    bool found     = false;
    size_t sectionAt = std::string::npos;

    for (size_t i = 0; i < lines.size(); ++i) {
        if (isSection(lines[i], "[Resolve]")) {
            inResolve = true;
            sectionAt = i;
            continue;
        }
        if (inResolve && isAnySection(lines[i])) inResolve = false;
        if (!inResolve) continue;

        // Rattrape aussi la ligne commentee que livrent les distributions.
        std::string t = SafeFile::trim(lines[i]);
        while (!t.empty() && (t[0] == '#' || t[0] == ' ')) t = SafeFile::trim(t.substr(1));

        const auto eq = t.find('=');
        if (eq == std::string::npos) continue;
        if (SafeFile::trim(t.substr(0, eq)) != key) continue;

        lines[i] = found ? ("#" + lines[i]) : entry;
        found = true;
    }

    if (!found) {
        if (sectionAt != std::string::npos)
            lines.insert(lines.begin() + static_cast<long>(sectionAt) + 1, entry);
        else
            lines.insert(lines.end(), { "[Resolve]", entry });  // section absente : la creer
    }

    std::ostringstream out;
    for (const auto& l : lines) out << l << '\n';
    if (!SafeFile::writeAtomic(CONF, out.str())) return false;

    return reloadResolved();
}

// Sans ce rechargement, la modification n'avait aucun effet avant le prochain
// redemarrage -- alors que la documentation du projet l'annonçait deja.
bool DNSSecurity::reloadResolved() {
    if (std::system("systemctl is-active --quiet systemd-resolved 2>/dev/null") != 0)
        return true;  // pas demarre : rien a recharger, la conf servira au boot
    return std::system("systemctl reload-or-restart systemd-resolved 2>/dev/null") == 0;
}

bool DNSSecurity::isDNSSECEnabled()       { return readKey("DNSSEC")     == "yes"; }
bool DNSSecurity::isDNSOverTLSEnabled()   { return readKey("DNSOverTLS") == "yes"; }
bool DNSSecurity::applyDNSSEC(bool e)     { return writeKey("DNSSEC",     e ? "yes" : "no"); }
bool DNSSecurity::applyDNSOverTLS(bool e) { return writeKey("DNSOverTLS", e ? "yes" : "no"); }
