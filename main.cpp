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

#include <string>
#include <vector>
#include <iostream>
#include <syslog.h>

using namespace ftxui;

struct Flag { bool on = false; };

static int runIntegrityCheck() {
    if (!FileIntegrity::hasBaseline())
        return 0;

    auto results = FileIntegrity::check();
    bool alert = false;

    openlog("spp-integrity", LOG_PID, LOG_DAEMON);
    for (const auto& r : results) {
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

    return alert ? 1 : 0;
}

int main(int argc, char* argv[]) {
    if (argc > 1 && std::string(argv[1]) == "--check")
        return runIntegrityCheck();

    auto screen = ScreenInteractive::Fullscreen();

    auto kernelOpts = KernelSecurity::kernelOptions();
    auto fsOpts     = KernelSecurity::fsOptions();
    auto netOpts    = KernelSecurity::netOptions();

    std::vector<Flag> kernelState(kernelOpts.size());
    std::vector<Flag> fsState(fsOpts.size());
    std::vector<Flag> netState(netOpts.size());

    for (size_t i = 0; i < kernelOpts.size(); ++i)
        kernelState[i].on = KernelSecurity::isHardened(kernelOpts[i]);
    for (size_t i = 0; i < fsOpts.size(); ++i)
        fsState[i].on = KernelSecurity::isHardened(fsOpts[i]);
    for (size_t i = 0; i < netOpts.size(); ++i)
        netState[i].on = KernelSecurity::isHardened(netOpts[i]);

    auto makeOption = [](const std::string& name, const std::string& detail, bool* state) -> Component {
        auto cb = Checkbox(name, state);
        return Renderer(cb, [cb, detail] {
            return vbox({
                cb->Render(),
                hbox({ text("   "), paragraph(detail) | color(Color::GrayDark) }),
                text(""),
            });
        });
    };

    Components kernelComps, fsComps, netComps;
    for (size_t i = 0; i < kernelOpts.size(); ++i)
        kernelComps.push_back(makeOption(kernelOpts[i].name, kernelOpts[i].detail, &kernelState[i].on));
    for (size_t i = 0; i < fsOpts.size(); ++i)
        fsComps.push_back(makeOption(fsOpts[i].name, fsOpts[i].detail, &fsState[i].on));
    for (size_t i = 0; i < netOpts.size(); ++i)
        netComps.push_back(makeOption(netOpts[i].name, netOpts[i].detail, &netState[i].on));

    auto optionsContainer = Container::Vertical({});
    for (auto& c : kernelComps) optionsContainer->Add(c);
    for (auto& c : fsComps)     optionsContainer->Add(c);
    for (auto& c : netComps)    optionsContainer->Add(c);

    std::vector<std::pair<std::string,std::string>> dnsOpts = {
        {"DNSSEC",
         "Verifie la signature cryptographique des reponses DNS."
         " Bloque le DNS spoofing et les attaques de type Kaminsky."},
        {"DNS over TLS",
         "Chiffre les requetes DNS via TLS. Empeche le FAI et les"
         " intermediaires de lire ou alterer vos resolutions DNS."},
    };

    std::vector<Flag> dnsState(dnsOpts.size());
    dnsState[0].on = DNSSecurity::isDNSSECEnabled();
    dnsState[1].on = DNSSecurity::isDNSOverTLSEnabled();

    Components dnsComps;
    for (size_t i = 0; i < dnsOpts.size(); ++i)
        dnsComps.push_back(makeOption(dnsOpts[i].first, dnsOpts[i].second, &dnsState[i].on));

    for (auto& c : dnsComps) optionsContainer->Add(c);

    auto memOpts     = Optimization::memoryOptions();
    auto netPerfOpts = Optimization::networkOptions();

    std::vector<Flag> memOptState(memOpts.size());
    std::vector<Flag> netPerfState(netPerfOpts.size());

    for (size_t i = 0; i < memOpts.size(); ++i)
        memOptState[i].on = KernelSecurity::isHardened(memOpts[i]);
    for (size_t i = 0; i < netPerfOpts.size(); ++i)
        netPerfState[i].on = KernelSecurity::isHardened(netPerfOpts[i]);

    Components memOptComps, netPerfComps;
    for (size_t i = 0; i < memOpts.size(); ++i)
        memOptComps.push_back(makeOption(memOpts[i].name, memOpts[i].detail, &memOptState[i].on));
    for (size_t i = 0; i < netPerfOpts.size(); ++i)
        netPerfComps.push_back(makeOption(netPerfOpts[i].name, netPerfOpts[i].detail, &netPerfState[i].on));

    for (auto& c : memOptComps)  optionsContainer->Add(c);
    for (auto& c : netPerfComps) optionsContainer->Add(c);

    bool sshRootDisabled = SSHSecurity::isRootLoginDisabled();
    auto sshComp = makeOption(
        "Bloquer les connexions root en SSH",
        "Interdit la connexion directe en root via SSH.",
        &sshRootDisabled
    );
    optionsContainer->Add(sshComp);

    auto nsOpts = NamespacesSecurity::options();
    std::vector<Flag> nsState(nsOpts.size());
    for (size_t i = 0; i < nsOpts.size(); ++i)
        nsState[i].on = NamespacesSecurity::isHardened(nsOpts[i]);

    Components nsComps;
    for (size_t i = 0; i < nsOpts.size(); ++i)
        nsComps.push_back(makeOption(nsOpts[i].name, nsOpts[i].detail, &nsState[i].on));
    for (auto& c : nsComps) optionsContainer->Add(c);

    bool selinuxPresent = SELinuxSecurity::isInstalled();
    bool aaPresent      = AppArmorSecurity::isInstalled();

    auto selinuxModeOpts = selinuxPresent ? SELinuxSecurity::modeOptions()    : std::vector<SELinuxOption>{};
    auto selinuxBoolOpts = selinuxPresent ? SELinuxSecurity::booleanOptions() : std::vector<SELinuxOption>{};

    std::vector<Flag> selinuxModeState(selinuxModeOpts.size());
    std::vector<Flag> selinuxBoolState(selinuxBoolOpts.size());

    for (size_t i = 0; i < selinuxModeOpts.size(); ++i)
        selinuxModeState[i].on = SELinuxSecurity::isHardened(selinuxModeOpts[i]);
    for (size_t i = 0; i < selinuxBoolOpts.size(); ++i)
        selinuxBoolState[i].on = SELinuxSecurity::isHardened(selinuxBoolOpts[i]);

    Components selinuxModeComps, selinuxBoolComps;
    for (size_t i = 0; i < selinuxModeOpts.size(); ++i)
        selinuxModeComps.push_back(makeOption(selinuxModeOpts[i].name, selinuxModeOpts[i].detail, &selinuxModeState[i].on));
    for (size_t i = 0; i < selinuxBoolOpts.size(); ++i)
        selinuxBoolComps.push_back(makeOption(selinuxBoolOpts[i].name, selinuxBoolOpts[i].detail, &selinuxBoolState[i].on));

    auto aaEnforceOpts = aaPresent ? AppArmorSecurity::enforcementOptions() : std::vector<AppArmorOption>{};
    auto aaProfileOpts = aaPresent ? AppArmorSecurity::profileOptions()     : std::vector<AppArmorOption>{};

    std::vector<Flag> aaEnforceState(aaEnforceOpts.size());
    std::vector<Flag> aaProfileState(aaProfileOpts.size());

    for (size_t i = 0; i < aaEnforceOpts.size(); ++i)
        aaEnforceState[i].on = AppArmorSecurity::isHardened(aaEnforceOpts[i]);
    for (size_t i = 0; i < aaProfileOpts.size(); ++i)
        aaProfileState[i].on = AppArmorSecurity::isHardened(aaProfileOpts[i]);

    Components aaEnforceComps, aaProfileComps;
    for (size_t i = 0; i < aaEnforceOpts.size(); ++i)
        aaEnforceComps.push_back(makeOption(aaEnforceOpts[i].name, aaEnforceOpts[i].detail, &aaEnforceState[i].on));
    for (size_t i = 0; i < aaProfileOpts.size(); ++i)
        aaProfileComps.push_back(makeOption(aaProfileOpts[i].name, aaProfileOpts[i].detail, &aaProfileState[i].on));

    int trackerLevel = (int)HostsBlocker::currentLevel();

    std::vector<std::string> trackerEntries = {
        "Aucune (par defaut)",
        "Minimum  —  19 domaines",
        "Basique  —  79 domaines",
        "Hard     — 156 domaines",
    };
    auto trackerRadio = Radiobox(&trackerEntries, &trackerLevel);

    bool serviceEnabled = FileIntegrity::isServiceEnabled();
    std::vector<IntegrityResult> integrityResults;
    std::string integrityMsg;
    bool integrityIsError  = false;
    bool baselineTampered  = false;

    auto serviceCheckbox = Checkbox("Activer au demarrage", &serviceEnabled);

    auto baselineBtn = Button("[ Creer baseline ]", [&] {
        bool ok = FileIntegrity::generateBaseline();
        integrityIsError = !ok;
        baselineTampered = false;
        integrityMsg = ok ? "Baseline creee et signee dans /var/lib/spp/"
                          : "Echec — lancez en sudo";
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

    std::string statusMsg;
    bool statusIsError = false;

    auto applyBtn = Button("[ Appliquer ]", [&] {
        int ok = 0, fail = 0;

        auto applyGroup = [&](const std::vector<SysctlOption>& opts,
                               const std::vector<Flag>& states) {
            for (size_t i = 0; i < opts.size(); ++i) {
                bool success = states[i].on
                    ? KernelSecurity::apply(opts[i])
                    : KernelSecurity::revert(opts[i]);
                success ? ++ok : ++fail;
            }
        };
        applyGroup(kernelOpts,  kernelState);
        applyGroup(fsOpts,      fsState);
        applyGroup(netOpts,     netState);
        applyGroup(memOpts,     memOptState);
        applyGroup(netPerfOpts, netPerfState);

        for (size_t i = 0; i < nsOpts.size(); ++i) {
            bool success = nsState[i].on
                ? NamespacesSecurity::apply(nsOpts[i])
                : NamespacesSecurity::revert(nsOpts[i]);
            success ? ++ok : ++fail;
        }

        // Persistance sysctl kernel : /etc/sysctl.d/99-spp.conf
        std::vector<std::pair<std::string,std::string>> persistEntries;
        auto collect = [&](const std::vector<SysctlOption>& opts, const std::vector<Flag>& states) {
            for (size_t i = 0; i < opts.size(); ++i)
                if (states[i].on)
                    persistEntries.push_back({ opts[i].key, opts[i].hardened });
        };
        collect(kernelOpts, kernelState);
        collect(fsOpts,     fsState);
        collect(netOpts,    netState);
        collect(memOpts,    memOptState);
        collect(netPerfOpts, netPerfState);
        KernelSecurity::writePersistenceConf(persistEntries) ? ++ok : ++fail;

        // Persistance namespaces : /etc/sysctl.d/99-spp-ns.conf
        std::vector<std::pair<std::string,std::string>> nsPersist;
        for (size_t i = 0; i < nsOpts.size(); ++i)
            if (nsState[i].on)
                nsPersist.push_back({ nsOpts[i].key, nsOpts[i].hardened });
        NamespacesSecurity::writePersistenceConf(nsPersist) ? ++ok : ++fail;

        DNSSecurity::applyDNSSEC(dnsState[0].on)    ? ++ok : ++fail;
        DNSSecurity::applyDNSOverTLS(dnsState[1].on) ? ++ok : ++fail;

        SSHSecurity::applyDisableRootLogin(sshRootDisabled) ? ++ok : ++fail;

        auto applySelinux = [&](const std::vector<SELinuxOption>& opts,
                                 const std::vector<Flag>& states) {
            for (size_t i = 0; i < opts.size(); ++i) {
                bool success = states[i].on
                    ? SELinuxSecurity::apply(opts[i])
                    : SELinuxSecurity::revert(opts[i]);
                success ? ++ok : ++fail;
            }
        };
        applySelinux(selinuxModeOpts, selinuxModeState);
        applySelinux(selinuxBoolOpts, selinuxBoolState);

        auto applyAppArmor = [&](const std::vector<AppArmorOption>& opts,
                                  const std::vector<Flag>& states) {
            for (size_t i = 0; i < opts.size(); ++i) {
                bool success = states[i].on
                    ? AppArmorSecurity::apply(opts[i])
                    : AppArmorSecurity::revert(opts[i]);
                success ? ++ok : ++fail;
            }
        };
        applyAppArmor(aaEnforceOpts, aaEnforceState);
        applyAppArmor(aaProfileOpts,  aaProfileState);

        bool hostsOk = HostsBlocker::apply((HostsBlocker::Level)trackerLevel);
        hostsOk ? ++ok : ++fail;

        if (serviceEnabled) {
            FileIntegrity::installServiceFile();
            FileIntegrity::enableService() ? ++ok : ++fail;
        } else {
            FileIntegrity::disableService() ? ++ok : ++fail;
        }

        statusIsError = (fail > 0);
        if (fail == 0)
            statusMsg = " OK — " + std::to_string(ok) + " changements appliques";
        else
            statusMsg = " " + std::to_string(ok) + " OK  |  " +
                        std::to_string(fail) + " echec  (lancez en sudo)";
    });

    auto cleanupBtn = Button("[ Supprimer SPP ]", [&] {
        auto r = Cleanup::removeAllTraces();
        statusIsError = (r.fail > 0);
        if (r.fail == 0)
            statusMsg = " Toutes les traces SPP ont ete supprimees";
        else
            statusMsg = " " + std::to_string(r.ok) + " OK  |  " +
                        std::to_string(r.fail) + " echec  (lancez en sudo)";
        // Reflete la suppression dans l'interface
        trackerLevel    = (int)HostsBlocker::NONE;
        serviceEnabled  = false;
        baselineTampered = false;
        integrityResults.clear();
        integrityMsg.clear();
        for (size_t i = 0; i < selinuxModeState.size(); ++i)
            selinuxModeState[i].on = SELinuxSecurity::isHardened(selinuxModeOpts[i]);
        for (size_t i = 0; i < selinuxBoolState.size(); ++i)
            selinuxBoolState[i].on = SELinuxSecurity::isHardened(selinuxBoolOpts[i]);
        for (size_t i = 0; i < aaEnforceState.size(); ++i)
            aaEnforceState[i].on = AppArmorSecurity::isHardened(aaEnforceOpts[i]);
        for (size_t i = 0; i < aaProfileState.size(); ++i)
            aaProfileState[i].on = AppArmorSecurity::isHardened(aaProfileOpts[i]);
    });

    auto quitBtn = Button("[ Quitter ]", screen.ExitLoopClosure());

    auto rightContainer = Container::Vertical({
        trackerRadio,
        serviceCheckbox,
        baselineBtn,
        verifyBtn,
    });
    for (auto& c : selinuxModeComps) optionsContainer->Add(c);
    for (auto& c : selinuxBoolComps) optionsContainer->Add(c);
    for (auto& c : aaEnforceComps)   optionsContainer->Add(c);
    for (auto& c : aaProfileComps)   optionsContainer->Add(c);

    auto layout = Container::Vertical({
        Container::Horizontal({
            optionsContainer,
            rightContainer,
        }),
        Container::Horizontal({applyBtn, cleanupBtn, quitBtn}),
    });

    auto renderer = Renderer(layout, [&] {
        auto sectionHeader = [](const std::string& title, Color c) -> Element {
            return hbox({
                text(" " + title + " ") | bold | color(c),
                separator() | color(c),
            });
        };

        std::vector<Element> optLines;
        optLines.push_back(sectionHeader("KERNEL", Color::Yellow));
        for (auto& c : kernelComps) optLines.push_back(c->Render());
        optLines.push_back(separator());
        optLines.push_back(sectionHeader("FILESYSTEM", Color::Yellow));
        for (auto& c : fsComps) optLines.push_back(c->Render());
        optLines.push_back(separator());
        optLines.push_back(sectionHeader("RESEAU", Color::Yellow));
        for (auto& c : netComps) optLines.push_back(c->Render());
        optLines.push_back(separator());
        optLines.push_back(sectionHeader("DNS", Color::Cyan));
        for (auto& c : dnsComps) optLines.push_back(c->Render());
        optLines.push_back(separator());
        optLines.push_back(sectionHeader("MEMOIRE", Color::Green));
        for (auto& c : memOptComps) optLines.push_back(c->Render());
        optLines.push_back(separator());
        optLines.push_back(sectionHeader("PERF RESEAU", Color::Green));
        for (auto& c : netPerfComps) optLines.push_back(c->Render());
        optLines.push_back(separator());
        optLines.push_back(sectionHeader("SSH", Color::Red));
        optLines.push_back(sshComp->Render());
        optLines.push_back(separator());
        optLines.push_back(sectionHeader("NAMESPACES", Color::Magenta));
        for (auto& c : nsComps) optLines.push_back(c->Render());
        if (selinuxPresent) {
            optLines.push_back(separator());
            optLines.push_back(sectionHeader("SELINUX", Color::Blue));
            for (auto& c : selinuxModeComps) optLines.push_back(c->Render());
            for (auto& c : selinuxBoolComps) optLines.push_back(c->Render());
        }
        if (aaPresent) {
            optLines.push_back(separator());
            optLines.push_back(sectionHeader("APPARMOR", Color::Blue));
            for (auto& c : aaEnforceComps)  optLines.push_back(c->Render());
            for (auto& c : aaProfileComps)  optLines.push_back(c->Render());
        }

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
            text(" Requiert sudo") | color(Color::GrayDark) | dim,
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

        intLines.push_back(filler());
        intLines.push_back(separator());
        intLines.push_back(text(" Baseline : /var/lib/spp/") | color(Color::GrayDark) | dim);

        auto integrityPanel = vbox(intLines);

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
                    integrityPanel  | border,
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
    return 0;
}
