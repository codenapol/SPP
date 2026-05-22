#include "HostsBlocker.hpp"
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
    std::ifstream in(HOSTS_PATH);
    if (!in.is_open()) return false;

    std::vector<std::string> preserved;
    std::string line;
    bool inBlock = false;

    while (std::getline(in, line)) {
        if (line.find(MARKER_BEGIN) != std::string::npos) { inBlock = true;  continue; }
        if (line.find(MARKER_END)   != std::string::npos) { inBlock = false; continue; }
        if (!inBlock)
            preserved.push_back(line);
    }
    in.close();

    std::ofstream out(HOSTS_PATH);
    if (!out.is_open()) return false;

    for (const auto& l : preserved)
        out << l << '\n';

    if (level != NONE) {
        out << '\n' << MARKER_BEGIN << ':' << levelName(level) << '\n';
        for (const auto& domain : domainsFor(level))
            out << "0.0.0.0 " << domain << '\n';
        out << MARKER_END << '\n';
    }

    return out.good();
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
        "t.co",
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
            return "Bloque 79 domaines (inclut Minimum) : pixels Twitter,\n"
                   "Pinterest, TikTok, Snap, Adobe Analytics, Microsoft\n"
                   "Clarity, Criteo, Outbrain, Taboola, Mixpanel, Amplitude.\n"
                   "Sites fonctionnent normalement. Faux positifs : quasi nuls.";
        case HARD:
            return "Bloque 156 domaines (inclut Basique) : session recording\n"
                   "(FullStory, LogRocket, CrazyEgg), DMP (LiveRamp, Lotame,\n"
                   "Bluekai), DSP (TradeDesk, MediaMath), Sentry, Bugsnag.\n"
                   "Peut casser certains chats live (Intercom, Drift).";
    }
    return "";
}
