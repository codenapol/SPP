#include "HostsBlocker.hpp"
#include "SafeFile.hpp"
#include <fstream>
#include <sstream>

const std::string HostsBlocker::HOSTS_PATH    = "/etc/hosts";
const std::string HostsBlocker::MARKER_BEGIN  = "# SPP-TRACKER-BEGIN";
const std::string HostsBlocker::MARKER_END    = "# SPP-TRACKER-END";

HostsBlocker::Level HostsBlocker::currentLevel() {
    std::ifstream f(HOSTS_PATH);
    if (!f.is_open()) return NONE;

    std::string line;
    while (std::getline(f, line)) {
        if (line.find(MARKER_BEGIN) == std::string::npos) continue;
        if (line.find(":HARD")    != std::string::npos) return HARD;
        if (line.find(":BASIQUE") != std::string::npos) return BASIQUE;
        if (line.find(":MINIMUM") != std::string::npos) return MINIMUM;
    }
    return NONE;
}

bool HostsBlocker::apply(Level level) {
    const std::string current = SafeFile::read(HOSTS_PATH);
    if (current.empty()) return false;

    SafeFile::backupOnce(HOSTS_PATH);

    std::vector<std::string> preserved;
    std::istringstream in(current);
    std::string line;
    bool inBlock = false;

    while (std::getline(in, line)) {
        if (line.find(MARKER_BEGIN) != std::string::npos) { inBlock = true;  continue; }
        if (line.find(MARKER_END)   != std::string::npos) { inBlock = false; continue; }
        if (!inBlock)
            preserved.push_back(line);
    }

    // Marqueur d'ouverture sans fermeture : le fichier a ete tronque par une
    // interruption anterieure. Poursuivre reviendrait a effacer tout ce qui
    // suit -- y compris la resolution de localhost.
    if (inBlock) return false;

    // Le bloc est precede d'une ligne vide, elle-meme conservee a la relecture :
    // sans cette normalisation, chaque application en ajoutait une de plus.
    while (!preserved.empty() && SafeFile::trim(preserved.back()).empty())
        preserved.pop_back();

    std::ostringstream out;
    for (const auto& l : preserved)
        out << l << '\n';

    if (level != NONE) {
        out << '\n' << MARKER_BEGIN << ':' << levelName(level) << '\n';
        for (const auto& domain : domainsFor(level))
            out << "0.0.0.0 " << domain << '\n';
        out << MARKER_END << '\n';
    }

    // Ecriture atomique : /etc/hosts est le fichier le plus expose ici, une
    // coupure en pleine troncature couperait la machine de localhost.
    return SafeFile::writeAtomic(HOSTS_PATH, out.str());
}

std::vector<std::string> HostsBlocker::domainsFor(Level level) {
    std::vector<std::string> result;

    auto append = [&](const std::vector<std::string>& src) {
        result.insert(result.end(), src.begin(), src.end());
    };

    if (level >= MINIMUM) append(minimumDomains());
    if (level >= BASIQUE) append(basiqueDomains());
    if (level >= HARD)    append(hardDomains());

    return result;
}

std::vector<std::string> HostsBlocker::minimumDomains() {
    return {
        "doubleclick.net",
        "www.doubleclick.net",
        "ads.doubleclick.net",
        "google-analytics.com",
        "www.google-analytics.com",
        "analytics.google.com",
        "googletagmanager.com",
        "www.googletagmanager.com",
        "googleadservices.com",
        "www.googleadservices.com",
        "connect.facebook.net",
        "pixel.facebook.com",
        "hotjar.com",
        "script.hotjar.com",
        "static.hotjar.com",
        "mouseflow.com",
        "cdn.mouseflow.com",
        "scorecardresearch.com",
        "b.scorecardresearch.com",
    };
}

std::vector<std::string> HostsBlocker::basiqueDomains() {
    return {
        "criteo.com",
        "dis.criteo.com",
        "static.criteo.net",
        "ad.criteortb.com",
        "adnxs.com",
        "ib.adnxs.com",
        "cdn.adnxs.com",
        "rubiconproject.com",
        "fastlane.rubiconproject.com",
        "pixel.rubiconproject.com",
        "pubmatic.com",
        "ads.pubmatic.com",
        "image6.pubmatic.com",
        "casalemedia.com",
        "bidswitch.net",
        "smartadserver.com",
        "eas.smartadserver.com",
        "media.net",
        "adservetx.media.net",
        "spotxchange.com",
        "spotx.tv",
        "outbrain.com",
        "widgets.outbrain.com",
        "taboola.com",
        "cdn.taboola.com",
        "api.taboola.com",
        "zemanta.com",
        "ads.twitter.com",
        "analytics.twitter.com",
        "ct.pinterest.com",
        "trk.pinterest.com",
        "tr.snapchat.com",
        "analytics.tiktok.com",
        "ads.tiktok.com",
        "omtrdc.net",
        "2o7.net",
        "demdex.net",
        "adobedc.net",
        "sc.omtrdc.net",
        "bat.bing.com",
        "clarity.microsoft.com",
        "c.clarity.ms",
        "fls-na.amazon-adsystem.com",
        "s.amazon-adsystem.com",
        "aax.amazon-adsystem.com",
        "mixpanel.com",
        "api.mixpanel.com",
        "cdn.mxpnl.com",
        "amplitude.com",
        "api.amplitude.com",
        "cdn.amplitude.com",
        "chartbeat.com",
        "chartbeat.net",
        "static.chartbeat.com",
        "parsely.com",
        "srv.pixel.parsely.com",
        "nr-data.net",
        "bam.nr-data.net",
        "newrelic.com",
    };
}

std::vector<std::string> HostsBlocker::hardDomains() {
    return {
        // Raccourcisseur de liens de Twitter/X : le bloquer casse TOUS les liens
        // t.co, y compris hors navigateur. Sa place est ici, pas en BASIQUE.
        "t.co",
        "fullstory.com",
        "rs.fullstory.com",
        "edge.fullstory.com",
        "heapanalytics.com",
        "cdn.heapanalytics.com",
        "sessioncam.com",
        "c.sessioncam.com",
        "logrocket.com",
        "cdn.lr-ingest.io",
        "r.lr-ingest.io",
        "crazyegg.com",
        "script.crazyegg.com",
        "smartlook.com",
        "rec.smartlook.com",
        "luckyorange.com",
        "cdn.luckyorange.com",
        "inspectlet.com",
        "hn.inspectlet.com",
        "segment.io",
        "cdn.segment.com",
        "api.segment.io",
        "kissmetrics.com",
        "doug1izaerwt3.cloudfront.net",
        "woopra.com",
        "static.woopra.com",
        "intercom.io",
        "widget.intercom.io",
        "js.intercom.io",
        "nexus.intercom.io",
        "api-iam.intercom.io",
        "drift.com",
        "js.driftt.com",
        "event.driftt.com",
        "addthis.com",
        "s7.addthis.com",
        "sharethis.com",
        "w.sharethis.com",
        "addtoany.com",
        "static.addtoany.com",
        "platform.linkedin.com",
        "snap.licdn.com",
        "ads.linkedin.com",
        "dc.ads.linkedin.com",
        "metrica.yandex.com",
        "mc.yandex.ru",
        "an.yandex.ru",
        "bluekai.com",
        "tags.bluekai.com",
        "rlcdn.com",
        "liveramp.com",
        "crwdcntrl.net",
        "ad.crwdcntrl.net",
        "eyeota.net",
        "moatads.com",
        "moat.com",
        "z.moatads.com",
        "integralads.com",
        "px.owneriq.net",
        "adsrvr.org",
        "match.adsrvr.org",
        "js.adsrvr.org",
        "mathtag.com",
        "pixel.mathtag.com",
        "triplelift.com",
        "tlx.3lift.com",
        "teads.tv",
        "a.teads.tv",
        "cloudflareinsights.com",
        "static.cloudflareinsights.com",
        "bugsnag.com",
        "sessions.bugsnag.com",
        "notify.bugsnag.com",
        "sentry.io",
        "browser.sentry-cdn.com",
        "piano.io",
        "at-o.net",
        "tags.tiqcdn.com",
    };
}

std::string HostsBlocker::levelName(Level level) {
    switch (level) {
        case MINIMUM: return "MINIMUM";
        case BASIQUE: return "BASIQUE";
        case HARD:    return "HARD";
        default:      return "NONE";
    }
}

std::string HostsBlocker::levelDescription(Level level) {
    switch (level) {
        case NONE:
            return "Aucun domaine bloque. /etc/hosts n'est pas modifie.\n"
                   "Les trackers se chargent normalement dans le navigateur.";
        case MINIMUM:
            return "Bloque 19 domaines : Google Analytics, Tag Manager,\n"
                   "DoubleClick, Facebook Pixel, Hotjar, Mouseflow.\n"
                   "Faux positifs : aucun. Niveau recommande pour debuter.";
        case BASIQUE:
            return "Bloque 78 domaines (inclut Minimum) : pixels Twitter,\n"
                   "Pinterest, TikTok, Snap, Adobe Analytics, Microsoft\n"
                   "Clarity, Criteo, Outbrain, Taboola, Mixpanel, Amplitude.\n"
                   "Sites fonctionnent normalement. Faux positifs : quasi nuls.";
        case HARD:
            return "Bloque 156 domaines (inclut Basique) : session recording\n"
                   "(FullStory, LogRocket, CrazyEgg), DMP (LiveRamp, Lotame,\n"
                   "Bluekai), DSP (TradeDesk, MediaMath), Sentry, Bugsnag.\n"
                   "Casse les liens t.co (Twitter/X) et les chats live\n"
                   "(Intercom, Drift), ainsi que la remontee d'erreurs.";
    }
    return "";
}
