#include "DNS.hpp"
#include <fstream>
#include <string>
#include <vector>

static const char* CONF = "/etc/systemd/resolved.conf";

std::string DNSSecurity::readKey(const std::string& key) {
    std::ifstream f(CONF);
    if (!f.is_open()) return "";
    std::string line;
    bool inResolve = false;
    while (std::getline(f, line)) {
        if (line == "[Resolve]") { inResolve = true; continue; }
        if (!inResolve) continue;
        if (!line.empty() && line[0] == '[') break;
        if (line.rfind(key + "=", 0) == 0)
            return line.substr(key.size() + 1);
    }
    return "";
}

bool DNSSecurity::writeKey(const std::string& key, const std::string& value) {
    std::ifstream fin(CONF);
    if (!fin.is_open()) return false;
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(fin, line))
        lines.push_back(line);
    fin.close();

    bool inResolve = false;
    bool found = false;
    for (auto& l : lines) {
        if (l == "[Resolve]") { inResolve = true; continue; }
        if (inResolve && !l.empty() && l[0] == '[') inResolve = false;
        if (!inResolve) continue;
        size_t s = 0;
        while (s < l.size() && (l[s] == '#' || l[s] == ' ')) ++s;
        if (l.substr(s).rfind(key + "=", 0) == 0) {
            l = key + "=" + value;
            found = true;
        }
    }

    if (!found) {
        for (size_t i = 0; i < lines.size(); ++i) {
            if (lines[i] == "[Resolve]") {
                lines.insert(lines.begin() + i + 1, key + "=" + value);
                found = true;
                break;
            }
        }
    }

    if (!found) return false;
    std::ofstream fout(CONF);
    if (!fout.is_open()) return false;
    for (const auto& l : lines) fout << l << '\n';
    return fout.good();
}

bool DNSSecurity::isDNSSECEnabled()      { return readKey("DNSSEC")     == "yes"; }
bool DNSSecurity::isDNSOverTLSEnabled()  { return readKey("DNSOverTLS") == "yes"; }
bool DNSSecurity::applyDNSSEC(bool e)    { return writeKey("DNSSEC",     e ? "yes" : "no"); }
bool DNSSecurity::applyDNSOverTLS(bool e){ return writeKey("DNSOverTLS", e ? "yes" : "no"); }
