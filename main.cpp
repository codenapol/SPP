#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include "modules/Kernel.hpp"
#include "modules/HostsBlocker.hpp"
#include "modules/FileIntegrity.hpp"
#include "modules/DNS.hpp"
#include "modules/Optimization.hpp"
#include "modules/Cleanup.hpp"
#include "modules/SSH.hpp"
#include "modules/SELinux.hpp"
#include "modules/AppArmor.hpp"
#include "modules/Namespaces.hpp"

#include <memory>
#include <string>
#include <vector>
#include <iostream>
#include <syslog.h>
#include <unistd.h>

using namespace ftxui;

// std::vector<bool> est compacte en bits : impossible d'en prendre l'adresse
// pour un Checkbox. Ce wrapper donne un bool adressable et stable.
struct Flag { bool on = false; };

// Codes de sortie du mode --check, exploites par systemd et le journal.
enum ExitCode { EXIT_OK = 0, EXIT_ANOMALY = 1, EXIT_TAMPERED = 2, EXIT_USAGE = 3 };

static int runIntegrityCheck() {
    if (!FileIntegrity::hasBaseline())
        return EXIT_OK;

    openlog("spp-integrity", LOG_PID, LOG_AUTHPRIV);

    // L'interface verifiait deja ce point, pas le mode automatique : une
    // baseline reecrite par un attaquant passait donc pour saine.
    if (FileIntegrity::isBaselineTampered()) {
        syslog(LOG_CRIT, "BASELINE FALSIFIEE - resultats non fiables");
        std::cerr << "[SPP] BASELINE FALSIFIEE — resultats non fiables\n";
        closelog();
        return EXIT_TAMPERED;
    }

    bool alert = false;
    for (const auto& r : FileIntegrity::check()) {
        if (r.status == IntegrityResult::MODIFIED) {
            syslog(LOG_WARNING, "MODIFIE : %s", r.path.c_str());
            std::cerr << "[SPP] MODIFIE : " << r.path << '\n';
            alert = true;
        } else if (r.status == IntegrityResult::MISSING) {
            syslog(LOG_CRIT, "ABSENT  : %s", r.path.c_str());
            std::cerr << "[SPP] ABSENT  : " << r.path << '\n';
            alert = true;
        }
    }
    closelog();

    return alert ? EXIT_ANOMALY : EXIT_OK;
}

// ─── groupes d'options ────────────────────────────────────────────────────────

// Rassemble une famille d'options et son etat. `initial` memorise ce qui etait
// vrai a l'ouverture : c'est lui qui permet de n'agir que sur ce que
// l'utilisateur a reellement change.
//
// Mod fournit les statiques available/isHardened/apply/revert. KernelSecurity,
// NamespacesSecurity, SELinuxSecurity et AppArmorSecurity partagent cette forme.
template <typename Mod, typename Opt>
struct Group {
    std::vector<Opt>  opts;
    std::vector<Flag> state;
    std::vector<Flag> initial;
    Components        comps;

    // Renvoie le nombre d'options effectivement traitees.
    int apply(int& ok, int& fail, std::vector<std::string>& journal) {
        int changed = 0;
        for (size_t i = 0; i < opts.size(); ++i) {
            // Une option non touchee n'est jamais reecrite : c'est ce qui
            // empeche SPP de degrader un reglage qu'il n'a pas pose.
            if (state[i].on == initial[i].on) continue;

            const bool success = state[i].on ? Mod::apply(opts[i]) : Mod::revert(opts[i]);
            success ? ++ok : ++fail;
            ++changed;
            if (success)
                journal.push_back((state[i].on ? "active : " : "desactive : ") + opts[i].name);
        }
        return changed;
    }

    void refresh() {
        for (size_t i = 0; i < opts.size(); ++i)
            state[i].on = Mod::isHardened(opts[i]);
        initial = state;
    }
};

// L'allocation sur le tas garantit que les bool* confies aux Checkbox restent
// valides : un Group renvoye par valeur les invaliderait a la moindre copie.
template <typename Mod, typename Opt, typename MakeFn>
std::shared_ptr<Group<Mod, Opt>> makeGroup(std::vector<Opt> opts,
                                           Component container,
                                           MakeFn&& makeOption) {
    auto g = std::make_shared<Group<Mod, Opt>>();
    g->opts = Mod::available(opts);  // les cles absentes du systeme disparaissent
    g->state.resize(g->opts.size());

    for (size_t i = 0; i < g->opts.size(); ++i)
        g->state[i].on = Mod::isHardened(g->opts[i]);
    g->initial = g->state;

    for (size_t i = 0; i < g->opts.size(); ++i) {
        g->comps.push_back(makeOption(g->opts[i].name, g->opts[i].detail, &g->state[i].on));
        container->Add(g->comps.back());
    }
    return g;
}

// ─── programme ────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    const std::string arg = (argc > 1) ? argv[1] : "";

    if (arg == "--help" || arg == "-h") {
        std::cout << "SPP — Systeme de Protection Patriote\n\n"
                  << "  spp           interface de durcissement (root requis)\n"
                  << "  spp --check   controle d'integrite ; 0 sain, 1 anomalie, 2 baseline falsifiee\n";
        return EXIT_OK;
    }

    // Sans root, toutes les lectures /etc echouent et l'interface affiche un
    // etat faux : tout parait non durci et chaque action echoue en silence.
    if (geteuid() != 0) {
        std::cerr << "SPP doit etre lance en root :  sudo spp\n";
        return EXIT_USAGE;
    }

    if (arg == "--check")
        return runIntegrityCheck();

    if (!arg.empty()) {
        std::cerr << "Option inconnue : " << arg << "  (voir spp --help)\n";
        return EXIT_USAGE;
    }

    auto screen = ScreenInteractive::Fullscreen();

    auto makeOption = [](const std::string& name, const std::string& detail, bool* state) -> Component {
        auto cb = Checkbox(name, state);
        // Convention : un detail prefixe "[!]" signale une option qui casse des
        // usages courants. Il s'affiche en rouge, pas en gris discret.
        const bool risky = detail.rfind("[!]", 0) == 0;
        return Renderer(cb, [cb, detail, risky] {
            return vbox({
                cb->Render(),
                hbox({ text("   "),
                       paragraph(detail) | color(risky ? Color::Red : Color::GrayDark) }),
                text(""),
            });
        });
    };

    auto optionsContainer = Container::Vertical({});

    // Les groupes sont construits dans l'ordre d'affichage : la navigation
    // clavier suit ainsi toujours ce que l'on voit a l'ecran.
    auto kernelG  = makeGroup<KernelSecurity>(KernelSecurity::kernelOptions(),  optionsContainer, makeOption);
    auto fsG      = makeGroup<KernelSecurity>(KernelSecurity::fsOptions(),      optionsContainer, makeOption);
    auto netG     = makeGroup<KernelSecurity>(KernelSecurity::netOptions(),     optionsContainer, makeOption);

    // DNS : deux reglages sans table d'options, traites a part.
    const bool dnsAvailable = DNSSecurity::isAvailable();
    std::vector<std::pair<std::string, std::string>> dnsOpts = {
        {"DNSSEC",
         "Verifie la signature cryptographique des reponses DNS."
         " Bloque le DNS spoofing et les attaques de type Kaminsky."},
        {"DNS over TLS",
         "Chiffre les requetes DNS via TLS. Empeche le FAI et les"
         " intermediaires de lire ou alterer vos resolutions DNS."},
    };
    std::vector<Flag> dnsState(dnsOpts.size());
    Components dnsComps;
    if (dnsAvailable) {
        dnsState[0].on = DNSSecurity::isDNSSECEnabled();
        dnsState[1].on = DNSSecurity::isDNSOverTLSEnabled();
        for (size_t i = 0; i < dnsOpts.size(); ++i) {
            dnsComps.push_back(makeOption(dnsOpts[i].first, dnsOpts[i].second, &dnsState[i].on));
            optionsContainer->Add(dnsComps.back());
        }
    }
    std::vector<Flag> dnsInitial = dnsState;

    auto memG     = makeGroup<KernelSecurity>(Optimization::memoryOptions(),  optionsContainer, makeOption);
    auto netPerfG = makeGroup<KernelSecurity>(Optimization::networkOptions(), optionsContainer, makeOption);

    // SSH : un seul reglage.
    const bool sshAvailable = SSHSecurity::isInstalled();
    bool sshRootDisabled = sshAvailable && SSHSecurity::isRootLoginDisabled();
    bool sshInitial      = sshRootDisabled;
    Components sshComps;
    if (sshAvailable) {
        sshComps.push_back(makeOption(
            "Bloquer les connexions root en SSH",
            "Interdit la connexion directe en root via SSH. Ecrit un fichier"
            " dedie dans sshd_config.d, sans toucher a la configuration systeme.",
            &sshRootDisabled));
        optionsContainer->Add(sshComps.back());
    }

    auto nsG = makeGroup<NamespacesSecurity>(NamespacesSecurity::options(), optionsContainer, makeOption);

    auto selModeG = makeGroup<SELinuxSecurity>(
        SELinuxSecurity::isInstalled() ? SELinuxSecurity::modeOptions() : std::vector<SELinuxOption>{},
        optionsContainer, makeOption);
    auto selBoolG = makeGroup<SELinuxSecurity>(
        SELinuxSecurity::isInstalled() ? SELinuxSecurity::booleanOptions() : std::vector<SELinuxOption>{},
        optionsContainer, makeOption);

    auto aaEnforceG = makeGroup<AppArmorSecurity>(
        AppArmorSecurity::isInstalled() ? AppArmorSecurity::enforcementOptions() : std::vector<AppArmorOption>{},
        optionsContainer, makeOption);
    auto aaProfileG = makeGroup<AppArmorSecurity>(
        AppArmorSecurity::isInstalled() ? AppArmorSecurity::profileOptions() : std::vector<AppArmorOption>{},
        optionsContainer, makeOption);

    // ─── panneau droit ────────────────────────────────────────────────────────

    int trackerLevel   = (int)HostsBlocker::currentLevel();
    int trackerInitial = trackerLevel;

    std::vector<std::string> trackerEntries = {
        "Aucune (par defaut)",
        "Minimum  —  19 domaines",
        "Basique  —  78 domaines",
        "Hard     — 156 domaines",
    };
    auto trackerRadio = Radiobox(&trackerEntries, &trackerLevel);

    bool serviceEnabled = FileIntegrity::isServiceEnabled();
    bool serviceInitial = serviceEnabled;
    std::vector<IntegrityResult> integrityResults;
    std::string integrityMsg;
    bool integrityIsError  = false;
    bool baselineTampered  = false;

    auto serviceCheckbox = Checkbox("Verification horaire au demarrage", &serviceEnabled);

    auto baselineBtn = Button("[ Creer baseline ]", [&] {
        bool ok = FileIntegrity::generateBaseline();
        integrityIsError = !ok;
        baselineTampered = false;
        integrityMsg = ok ? "Baseline creee et signee dans /var/lib/spp/"
                          : "Echec — fichier critique illisible";
        if (ok) integrityResults = FileIntegrity::check();
    });

    auto verifyBtn = Button("[ Verifier ]", [&] {
        if (!FileIntegrity::hasBaseline()) {
            integrityIsError = true;
            integrityMsg = "Aucune baseline — creez-en une d'abord";
            return;
        }
        baselineTampered = FileIntegrity::isBaselineTampered();
        if (baselineTampered) {
            integrityIsError = true;
            integrityMsg = "ALERTE : La baseline a ete falsifiee !";
            integrityResults = FileIntegrity::check();
            return;
        }
        integrityResults = FileIntegrity::check();
        bool anyBad = false;
        for (const auto& r : integrityResults)
            if (r.status != IntegrityResult::OK) { anyBad = true; break; }
        integrityIsError = anyBad;
        integrityMsg = anyBad ? "Anomalies detectees !" : "Tous les fichiers sont integres";
    });

    // ─── actions ──────────────────────────────────────────────────────────────

    std::string statusMsg;
    bool statusIsError = false;

    // Relit l'etat reel du systeme. Appelee apres chaque action : une case qui
    // se recoche signale que l'operation n'a pas abouti.
    auto refreshAll = [&] {
        kernelG->refresh(); fsG->refresh(); netG->refresh();
        memG->refresh(); netPerfG->refresh(); nsG->refresh();
        selModeG->refresh(); selBoolG->refresh();
        aaEnforceG->refresh(); aaProfileG->refresh();

        if (dnsAvailable) {
            dnsState[0].on = DNSSecurity::isDNSSECEnabled();
            dnsState[1].on = DNSSecurity::isDNSOverTLSEnabled();
        }
        dnsInitial = dnsState;

        if (sshAvailable) sshRootDisabled = SSHSecurity::isRootLoginDisabled();
        sshInitial = sshRootDisabled;

        trackerLevel   = (int)HostsBlocker::currentLevel();
        trackerInitial = trackerLevel;
        serviceEnabled = FileIntegrity::isServiceEnabled();
        serviceInitial = serviceEnabled;
    };

    // Declares avant applyBtn : celui-ci desarme la confirmation de suppression.
    std::string cleanupLabel = "[ Supprimer SPP ]";
    bool cleanupArmed = false;

    auto applyBtn = Button("[ Appliquer ]", [&] {
        cleanupArmed = false;
        cleanupLabel = "[ Supprimer SPP ]";

        int ok = 0, fail = 0;
        std::vector<std::string> journal;

        int sysctlChanges = 0;
        sysctlChanges += kernelG->apply(ok, fail, journal);
        sysctlChanges += fsG->apply(ok, fail, journal);
        sysctlChanges += netG->apply(ok, fail, journal);
        sysctlChanges += memG->apply(ok, fail, journal);
        sysctlChanges += netPerfG->apply(ok, fail, journal);

        const int nsChanges = nsG->apply(ok, fail, journal);

        // La persistance liste TOUTES les options cochees, pas seulement celles
        // qui viennent de changer : le fichier decrit l'etat vise, pas le delta.
        if (sysctlChanges > 0) {
            std::vector<std::pair<std::string, std::string>> entries;
            auto collect = [&entries](const auto& g) {
                for (size_t i = 0; i < g->opts.size(); ++i)
                    if (g->state[i].on)
                        entries.push_back({ g->opts[i].key, g->opts[i].hardened });
            };
            collect(kernelG); collect(fsG); collect(netG);
            collect(memG);    collect(netPerfG);
            KernelSecurity::writePersistenceConf(entries) ? ++ok : ++fail;
        }

        if (nsChanges > 0) {
            std::vector<std::pair<std::string, std::string>> entries;
            for (size_t i = 0; i < nsG->opts.size(); ++i)
                if (nsG->state[i].on)
                    entries.push_back({ nsG->opts[i].key, nsG->opts[i].hardened });
            NamespacesSecurity::writePersistenceConf(entries) ? ++ok : ++fail;
        }

        if (dnsAvailable) {
            if (dnsState[0].on != dnsInitial[0].on)
                DNSSecurity::applyDNSSEC(dnsState[0].on) ? ++ok : ++fail;
            if (dnsState[1].on != dnsInitial[1].on)
                DNSSecurity::applyDNSOverTLS(dnsState[1].on) ? ++ok : ++fail;
        }

        // Aucun redemarrage de sshd si le reglage n'a pas bouge.
        if (sshAvailable && sshRootDisabled != sshInitial) {
            SSHSecurity::applyDisableRootLogin(sshRootDisabled) ? ++ok : ++fail;
            journal.push_back(sshRootDisabled ? "active : blocage root SSH"
                                              : "desactive : blocage root SSH");
        }

        selModeG->apply(ok, fail, journal);
        selBoolG->apply(ok, fail, journal);
        aaEnforceG->apply(ok, fail, journal);
        aaProfileG->apply(ok, fail, journal);

        if (trackerLevel != trackerInitial) {
            HostsBlocker::apply((HostsBlocker::Level)trackerLevel) ? ++ok : ++fail;
            journal.push_back("bloqueur de trackers : " +
                              HostsBlocker::levelName((HostsBlocker::Level)trackerLevel));
        }

        if (serviceEnabled != serviceInitial) {
            if (serviceEnabled) {
                bool done = FileIntegrity::installServiceFile() && FileIntegrity::enableService();
                done ? ++ok : ++fail;
            } else {
                FileIntegrity::disableService() ? ++ok : ++fail;
            }
            journal.push_back(serviceEnabled ? "active : controle d'integrite periodique"
                                             : "desactive : controle d'integrite periodique");
        }

        // Trace d'audit : un durcissement doit laisser une trace de ce qu'il a change.
        if (!journal.empty()) {
            openlog("spp", LOG_PID, LOG_AUTHPRIV);
            for (const auto& line : journal)
                syslog(LOG_NOTICE, "%s", line.c_str());
            closelog();
        }

        refreshAll();

        statusIsError = (fail > 0);
        if (ok == 0 && fail == 0)
            statusMsg = " Aucun changement a appliquer";
        else if (fail == 0)
            statusMsg = " OK — " + std::to_string(ok) + " changement(s) applique(s)";
        else
            statusMsg = " " + std::to_string(ok) + " OK  |  " +
                        std::to_string(fail) + " echec(s)";
    });

    // Bouton destructif : il exige une seconde pression, son libelle changeant
    // entre-temps. Il jouxte [ Appliquer ], une frappe suffisait auparavant.
    auto cleanupBtn = Button(&cleanupLabel, [&] {
        if (!cleanupArmed) {
            cleanupArmed  = true;
            cleanupLabel  = "[ Confirmer ? ]";
            statusIsError = true;
            statusMsg = " Retire les reglages SPP et restaure l'etat d'origine — confirmez";
            return;
        }
        cleanupArmed = false;
        cleanupLabel = "[ Supprimer SPP ]";

        auto r = Cleanup::removeAllTraces();

        openlog("spp", LOG_PID, LOG_AUTHPRIV);
        syslog(LOG_NOTICE, "desinstallation : %d restaure(s), %d echec(s)", r.ok, r.fail);
        closelog();

        baselineTampered = false;
        integrityResults.clear();
        integrityMsg.clear();
        refreshAll();  // relit tout : l'ancien code ne rafraichissait que SELinux/AppArmor

        statusIsError = (r.fail > 0);
        statusMsg = (r.fail == 0)
            ? " Reglages SPP retires, etat d'origine restaure"
            : " " + std::to_string(r.ok) + " OK  |  " + std::to_string(r.fail) + " echec(s)";
    });

    auto quitBtn = Button("[ Quitter ]", screen.ExitLoopClosure());

    auto rightContainer = Container::Vertical({
        trackerRadio,
        serviceCheckbox,
        baselineBtn,
        verifyBtn,
    });

    auto layout = Container::Vertical({
        Container::Horizontal({
            optionsContainer,
            rightContainer,
        }),
        Container::Horizontal({applyBtn, cleanupBtn, quitBtn}),
    });

    // ─── rendu ────────────────────────────────────────────────────────────────

    auto renderer = Renderer(layout, [&] {
        auto sectionHeader = [](const std::string& title, Color c) -> Element {
            return hbox({
                text(" " + title + " ") | bold | color(c),
                separator() | color(c),
            });
        };

        std::vector<Element> optLines;
        // Une section vide (module absent, options filtrees) ne s'affiche pas.
        // Un titre vide prolonge la section precedente, sans nouvel en-tete.
        auto pushSection = [&](const std::string& title, Color c, const Components& comps) {
            if (comps.empty()) return;
            if (!title.empty()) {
                if (!optLines.empty()) optLines.push_back(separator());
                optLines.push_back(sectionHeader(title, c));
            }
            for (const auto& comp : comps) optLines.push_back(comp->Render());
        };

        pushSection("KERNEL",      Color::Yellow,  kernelG->comps);
        pushSection("FILESYSTEM",  Color::Yellow,  fsG->comps);
        pushSection("RESEAU",      Color::Yellow,  netG->comps);
        pushSection("DNS",         Color::Cyan,    dnsComps);
        pushSection("MEMOIRE",     Color::Green,   memG->comps);
        pushSection("PERF RESEAU", Color::Green,   netPerfG->comps);
        pushSection("SSH",         Color::Red,     sshComps);
        pushSection("NAMESPACES",  Color::Magenta, nsG->comps);
        pushSection("SELINUX",     Color::Blue,    selModeG->comps);
        pushSection("",            Color::Blue,    selBoolG->comps);
        pushSection("APPARMOR",    Color::Blue,    aaEnforceG->comps);
        pushSection("",            Color::Blue,    aaProfileG->comps);

        auto trackerPanel = vbox({
            sectionHeader("BLOQUEUR DE TRACKERS", Color::Cyan),
            text(""),
            trackerRadio->Render(),
            text(""),
            separator(),
            paragraph(HostsBlocker::levelDescription(
                (HostsBlocker::Level)trackerLevel
            )) | color(Color::GrayDark),
            filler(),
            separator(),
            text(" Modifie /etc/hosts") | color(Color::Yellow) | dim,
            text(" Contenu original preserve") | color(Color::GrayDark) | dim,
        });

        std::vector<Element> intLines;
        intLines.push_back(sectionHeader("INTEGRITE FICHIERS", Color::Magenta));
        intLines.push_back(text(""));
        intLines.push_back(serviceCheckbox->Render());
        intLines.push_back(text(""));
        intLines.push_back(baselineBtn->Render());
        intLines.push_back(verifyBtn->Render());

        if (!integrityResults.empty()) {
            intLines.push_back(separator());
            if (baselineTampered) {
                intLines.push_back(
                    text(" BASELINE FALSIFIEE — RESULTATS NON FIABLES") | color(Color::Red) | bold
                );
                intLines.push_back(separator());
            }
            for (const auto& r : integrityResults) {
                std::string mark;
                Color col;
                if (baselineTampered) {
                    mark = " ??? ";
                    col  = Color::Red;
                } else {
                    switch (r.status) {
                        case IntegrityResult::OK:          mark = " OK  "; col = Color::Green;  break;
                        case IntegrityResult::MODIFIED:    mark = " MOD "; col = Color::Red;    break;
                        case IntegrityResult::MISSING:     mark = " ABS "; col = Color::Red;    break;
                        case IntegrityResult::NO_BASELINE: mark = "  ?  "; col = Color::Yellow; break;
                    }
                }
                intLines.push_back(hbox({
                    text(mark) | color(col) | bold,
                    text(r.label) | color(col),
                }));
            }
        }

        if (!integrityMsg.empty()) {
            intLines.push_back(separator());
            intLines.push_back(
                text(" " + integrityMsg)
                | color(integrityIsError ? Color::Red : Color::Green)
            );
        }

        auto integrityPanel = vbox({
            vbox(intLines) | vscroll_indicator | frame | flex,
            separator(),
            text(" Baseline : /var/lib/spp/") | color(Color::GrayDark) | dim,
        });

        Element status;
        if (statusMsg.empty()) {
            status = text("  Cochees = activer | Decochees = desactiver  —  puis Appliquer")
                     | color(Color::GrayDark);
        } else {
            status = text(statusMsg)
                     | (statusIsError ? color(Color::Red) : color(Color::Green));
        }

        return vbox({
            hbox({
                text(" SPP") | bold | color(Color::Red),
                text(" — Systeme de Protection Patriote ") | bold,
            }) | border,

            hbox({
                vbox(optLines) | vscroll_indicator | frame | flex | border,
                vbox({
                    trackerPanel    | border | flex,
                    integrityPanel  | border | flex,
                }) | size(WIDTH, EQUAL, 38),
            }) | flex,

            hbox({
                status | flex,
                applyBtn->Render(),
                text("  "),
                cleanupBtn->Render() | color(Color::Red),
                text("  "),
                quitBtn->Render(),
                text(" "),
            }) | border,
        });
    });

    screen.Loop(renderer);
    return EXIT_OK;
}
