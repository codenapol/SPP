#include "State.hpp"
#include "SafeFile.hpp"

#include <sstream>
#include <cerrno>
#include <unistd.h>
#include <sys/stat.h>

namespace SppState {

const std::string STATE_PATH = "/var/lib/spp/original.state";

using Entries = std::vector<std::pair<std::string, std::string>>;

static Entries parse() {
    Entries out;
    std::istringstream in(SafeFile::read(STATE_PATH));
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto sep = line.find('=');
        if (sep == std::string::npos) continue;
        out.push_back({ SafeFile::trim(line.substr(0, sep)),
                        SafeFile::trim(line.substr(sep + 1)) });
    }
    return out;
}

static bool serialize(const Entries& entries) {
    ::mkdir("/var/lib/spp", 0700);

    std::ostringstream out;
    out << "# SPP - etat du systeme avant toute intervention.\n"
        << "# Genere automatiquement. Ne pas editer : c'est ce fichier qui permet\n"
        << "# de restaurer la machine telle qu'elle etait.\n";
    for (const auto& [key, value] : entries)
        out << key << '=' << value << '\n';

    return SafeFile::writeAtomic(STATE_PATH, out.str(), 0600);
}

Entries all() { return parse(); }

bool hasOriginal(const std::string& key) {
    for (const auto& [k, v] : parse())
        if (k == key) return true;
    return false;
}

std::string original(const std::string& key) {
    for (const auto& [k, v] : parse())
        if (k == key) return v;
    return "";
}

void recordOriginal(const std::string& key, const std::string& value) {
    // Une valeur vide signifie que la lecture a echoue : ne rien enregistrer
    // vaut mieux qu'enregistrer un etat d'origine faux.
    if (key.empty() || value.empty()) return;
    if (value.find('\n') != std::string::npos) return;

    Entries entries = parse();
    for (const auto& [k, v] : entries)
        if (k == key) return;  // deja capture : l'original ne change jamais

    entries.push_back({ key, value });
    serialize(entries);
}

bool purge() {
    return ::unlink(STATE_PATH.c_str()) == 0 || errno == ENOENT;
}

}  // namespace SppState
