#pragma once
#include <string>
#include <utility>
#include <vector>

// Memoire de l'etat d'origine du systeme.
//
// La colonne `defaults` des tables d'options est codee en dur et ne correspond
// pas a la realite (verifie : fs.suid_dumpable vaut 0 et non 1,
// tcp_syncookies vaut 1 et non 0, perf_event_paranoid vaut 3 et non 1).
// S'y fier pour restaurer degrade le systeme.
//
// Ce module enregistre la valeur reellement observee, une seule fois, juste
// avant la toute premiere ecriture de SPP sur une cle. C'est cette valeur qui
// fait foi pour toute restauration ulterieure.
namespace SppState {

void        recordOriginal(const std::string& key, const std::string& value);
bool        hasOriginal(const std::string& key);
std::string original(const std::string& key);

std::vector<std::pair<std::string, std::string>> all();
bool purge();

extern const std::string STATE_PATH;

}  // namespace SppState
