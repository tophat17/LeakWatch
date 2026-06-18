"""Beginner-friendly knowledge base of common home-server apps.

For each app we record:
  * category   - what kind of app it is, in plain words
  * level      - how it relates to a VPN:
        critical    -> MUST be behind a VPN (exposed = big problem)
        recommended -> should be behind a VPN (exposed = worth fixing)
        gateway     -> this IS the VPN other apps route through
        server      -> should use your normal/server IP (a VPN would break it)
        optional    -> up to you; no strong opinion
        unknown     -> we don't recognise it
  * why          - one or two sentences, written for someone new to this
  * what_to_do   - the concrete action to take
  * learn_more   - a longer, friendly explanation for the detail panel

Matching is done by looking for keywords inside the container name + image.
"""
from __future__ import annotations

from dataclasses import dataclass

LEVEL_CRITICAL = "critical"
LEVEL_RECOMMENDED = "recommended"
LEVEL_GATEWAY = "gateway"
LEVEL_SERVER = "server"
LEVEL_OPTIONAL = "optional"
LEVEL_UNKNOWN = "unknown"

LEVEL_LABEL = {
    LEVEL_CRITICAL: "VPN required",
    LEVEL_RECOMMENDED: "VPN recommended",
    LEVEL_GATEWAY: "VPN gateway",
    LEVEL_SERVER: "No VPN needed",
    LEVEL_OPTIONAL: "VPN optional",
    LEVEL_UNKNOWN: "No recommendation",
}


@dataclass
class AppInfo:
    name: str
    category: str
    level: str
    why: str
    what_to_do: str
    learn_more: str

    def as_dict(self) -> dict:
        return {
            "name": self.name, "category": self.category, "level": self.level,
            "level_label": LEVEL_LABEL.get(self.level, "No recommendation"),
            "why": self.why, "what_to_do": self.what_to_do, "learn_more": self.learn_more,
        }


# Each entry: (keywords, AppInfo). First match wins, so list specific before generic.
_ROUTE_VPN = ("Route this container's network through a VPN container "
              "(for example gluetun, or a binhex *-vpn image) so its internet "
              "traffic leaves through the VPN instead of your home connection.")

CATALOG = [
    # ---- VPN gateways (the tunnel itself) ----
    (["gluetun", "wireguard", "openvpn", "-vpn"], AppInfo(
        "VPN gateway", "VPN tunnel provider", LEVEL_GATEWAY,
        "This container provides the VPN tunnel that other apps route through. Its public IP should be the VPN's, not your home IP.",
        "Make sure it shows a VPN provider IP. If it shows your server IP, the tunnel is down and everything behind it is exposed.",
        "A VPN gateway (like gluetun) creates one shared VPN connection. Other containers set their network to 'container:thisone' so all their traffic exits through the tunnel. If this gateway leaks, every app behind it leaks too, so it's the most important one to keep healthy.")),

    # ---- Torrent clients (critical) ----
    (["qbittorrent", "qbit", "deluge", "transmission", "rtorrent", "rutorrent", "flood", "torrent"], AppInfo(
        "Torrent / P2P client", "Torrent download client", LEVEL_CRITICAL,
        "Torrent traffic is peer-to-peer: every peer you connect to can see the IP address you're downloading from, and your ISP can see you're torrenting. Without a VPN that's your real home IP.",
        _ROUTE_VPN,
        "Torrent clients share files directly with strangers (peers). Those peers, and companies that monitor torrent swarms, record the IP they see. If that's your home IP, it's tied to you and your ISP. Running the client behind a VPN replaces your home IP with the VPN's, so your real address stays private. This is the single most important app to keep on a VPN.")),

    # ---- Usenet clients (critical) ----
    (["sabnzbd", "sabnzb", "nzbget", "usenet"], AppInfo(
        "Usenet downloader", "Usenet download client", LEVEL_CRITICAL,
        "Usenet downloads come from servers that log the connecting IP. Many people prefer their home IP never appears in those logs.",
        _ROUTE_VPN,
        "Usenet clients download from news servers over an encrypted connection, but the server still sees the IP that connected. A VPN keeps your real home IP out of those logs. Usenet providers usually allow VPNs - just make sure the client's traffic goes through the tunnel.")),

    # ---- Download managers (recommended) ----
    (["jdownloader", "pyload", "aria2"], AppInfo(
        "Download manager", "File-host downloader", LEVEL_RECOMMENDED,
        "Grabs files from public file hosts, which see and may rate-limit your IP. A VPN keeps your home IP private.",
        _ROUTE_VPN,
        "Download managers fetch files from file-hosting sites. Those sites log your IP and sometimes throttle or block home connections. A VPN hides your real IP and can avoid some limits. Recommended, though less critical than torrents.")),

    # ---- Indexers / proxies (recommended) ----
    (["prowlarr", "jackett"], AppInfo(
        "Indexer manager", "Torrent/Usenet indexer proxy", LEVEL_RECOMMENDED,
        "This talks to torrent and usenet indexer sites on your behalf. Some indexers block or log home IPs, and your searches reveal what you're looking for.",
        _ROUTE_VPN,
        "Indexer managers (Prowlarr, Jackett) connect to tracker and indexer websites to search for content. Those sites see your IP and your search queries. Routing through a VPN keeps your home IP and search activity private, and avoids indexers that block residential IPs.")),
    (["flaresolverr"], AppInfo(
        "Cloudflare solver", "Captcha / Cloudflare bypass proxy", LEVEL_RECOMMENDED,
        "Makes web requests to get past Cloudflare checks for your indexers. Those requests use whatever IP it has - ideally the VPN's, not your home IP.",
        _ROUTE_VPN,
        "FlareSolverr opens pages to solve Cloudflare 'are you human' challenges so your indexers can read them. Because it browses sites directly, it's best routed through the same VPN as your indexers so those requests don't expose your home IP.")),

    # ---- *arr automation (recommended, softer) ----
    (["sonarr", "radarr", "lidarr", "readarr", "whisparr", "mylar", "boxarr"], AppInfo(
        "Media automation (*arr)", "Library manager / automation", LEVEL_RECOMMENDED,
        "These tell your download client what to grab and talk to indexers. The actual downloading should go through your VPN'd client, but routing these through a VPN too keeps indexer traffic private.",
        "Recommended behind a VPN. At minimum, make sure the download client they feed (qBittorrent, SABnzbd, etc.) is on a VPN.",
        "The *arr apps (Sonarr for TV, Radarr for movies, etc.) organise your library and hand jobs to your download client and indexers. The risky part - the actual download - happens in the client, so the client MUST be on a VPN. Putting the *arr apps on a VPN too is good practice because they query indexers, but it's a softer recommendation.")),
    (["bazarr"], AppInfo(
        "Subtitle automation", "Subtitle downloader", LEVEL_OPTIONAL,
        "Downloads subtitles from public subtitle sites. Low risk, but a VPN keeps even this traffic private.",
        "Optional. Fine on your server IP; route through a VPN only if you want everything private.",
        "Bazarr fetches subtitle files from sites like OpenSubtitles. This is low-risk traffic, so a VPN is optional. Most people leave it on the normal connection.")),

    # ---- Media servers (server / no VPN) ----
    (["plex", "jellyfin", "emby"], AppInfo(
        "Media server", "Media streaming server", LEVEL_SERVER,
        "This streams your media to your devices and needs to be reachable directly. A VPN would break remote access and direct play.",
        "Use your normal server IP. Do NOT put a media server behind a VPN.",
        "Media servers (Plex, Jellyfin, Emby) need people and apps to connect TO them, often from outside your home. They rely on your normal internet connection and port forwarding/relays. Putting one behind a VPN usually breaks remote streaming and is unnecessary - the server isn't hiding, it's hosting.")),
    (["tautulli", "overseerr", "jellyseerr", "ombi", "petio"], AppInfo(
        "Media companion", "Requests / stats for media server", LEVEL_SERVER,
        "Works alongside your media server and is usually accessed directly by you and your users. No VPN needed.",
        "Use your normal server IP.",
        "These add request pages or viewing stats to your media server. Like the media server itself, they're meant to be reached directly, so they should use your normal connection rather than a VPN.")),

    # ---- DDNS (must use real IP) ----
    (["cloudflare-ddns", "ddns", "duckdns", "dyndns"], AppInfo(
        "Dynamic DNS updater", "Keeps your domain pointed at home", LEVEL_SERVER,
        "This tells the internet your home's real IP address so your domain keeps working. A VPN would make it publish the wrong IP.",
        "Use your normal server IP. Do NOT route DDNS through a VPN.",
        "A DDNS updater watches your home's public IP and updates your domain name whenever it changes, so things like remote access keep working. It MUST see your real home IP - if it ran through a VPN it would publish the VPN's IP and your services would become unreachable.")),

    # ---- Local utilities / serving (no VPN) ----
    (["filebrowser", "audiobookshelf", "calibre", "navidrome", "komga", "kavita", "immich", "photoprism", "nextcloud"], AppInfo(
        "Local content server", "Files / books / photos server", LEVEL_SERVER,
        "Serves your own files to you and is accessed directly. No VPN needed.",
        "Use your normal server IP.",
        "These host your own content (files, audiobooks, photos, etc.) for you to reach directly, usually on your local network or via your own domain. They don't make risky outbound connections, so a VPN isn't needed and could complicate access.")),
    (["organizr", "homarr", "heimdall", "homepage", "dashy", "flame"], AppInfo(
        "Dashboard", "Home dashboard / start page", LEVEL_SERVER,
        "A web page you open to launch your other apps. Accessed directly, no VPN needed.",
        "Use your normal server IP.",
        "Dashboards are just a landing page linking to your services. You open them directly, so they use your normal connection.")),
    (["clamav", "diskspeed", "scrutiny", "netdata", "uptime"], AppInfo(
        "Server utility", "Monitoring / maintenance tool", LEVEL_SERVER,
        "A local maintenance/monitoring tool. It doesn't need to hide its IP.",
        "Use your normal server IP.",
        "These keep your server healthy (antivirus signatures, disk speed, monitoring). Their traffic is harmless updates/telemetry, so no VPN is required.")),

    # ---- Sync / backup (optional) ----
    (["syncthing", "resilio"], AppInfo(
        "File sync", "Peer-to-peer file sync", LEVEL_OPTIONAL,
        "Syncs your files between your own devices, sometimes via public relays. A VPN is optional and can interfere with discovery.",
        "Optional - usually fine on your server IP.",
        "Syncthing keeps folders in sync across your devices. It can use public relay/discovery servers, which see your IP. It's your own data so risk is low; a VPN is optional and can sometimes break device discovery.")),
    (["duplicacy", "duplicati", "restic", "borg", "kopia"], AppInfo(
        "Backup tool", "Cloud/remote backup", LEVEL_OPTIONAL,
        "Backs up your data, often to a cloud provider. Your backups are encrypted; a VPN is optional.",
        "Optional - usually fine on your server IP.",
        "Backup tools upload (usually encrypted) copies of your data to a remote/cloud destination. The data is already protected by encryption, so a VPN is optional and mainly a personal-privacy preference.")),
    # ---- media requests ----
    (["seerr", "jelly-request", "jellyrequest"], AppInfo(
        "Media requests", "Requests page for your media server", LEVEL_SERVER,
        "A page where you and your users request movies/shows. Accessed directly; no VPN needed.",
        "Use your normal server IP.",
        "Request apps (Overseerr/Jellyseerr/Seerr) let people ask for content, which your *arr apps then fetch. You open them directly, so they use your normal connection.")),
    # ---- reverse proxies ----
    (["nginx-proxy-manager", "nginxproxymanager", "swag", "traefik", "caddy", "npmplus"], AppInfo(
        "Reverse proxy", "Routes inbound web traffic to your apps", LEVEL_SERVER,
        "This accepts incoming connections from the internet and forwards them to your apps. It must use your real connection, never a VPN.",
        "Use your normal server IP. Do NOT route a reverse proxy through a VPN.",
        "A reverse proxy is the front door to your server - it receives visitors and sends them to the right app. It has to be reachable on your real IP, so a VPN would make your sites unreachable.")),
    # ---- inbound tunnels ----
    (["cloudflared", "cloudflare-tunnel", "argo-tunnel"], AppInfo(
        "Cloudflare Tunnel", "Secure inbound tunnel (Cloudflare)", LEVEL_SERVER,
        "This creates Cloudflare's own secure tunnel so people can reach your apps. It is its own protection and should use your normal connection.",
        "Use your normal server IP. Do not add another VPN on top.",
        "Cloudflare Tunnel makes an outbound connection to Cloudflare so visitors reach your services without opening ports. It is already a secure tunnel; adding a separate VPN is not needed and can break it.")),
    # ---- container management ----
    (["portainer", "dockge", "yacht", "dozzle", "watchtower"], AppInfo(
        "Container management", "Docker management tool", LEVEL_SERVER,
        "A tool you use to manage Docker. Accessed directly by you; no VPN needed.",
        "Use your normal server IP.",
        "These manage or watch your Docker containers and are used by you directly. They do not need to hide their IP.")),
    # ---- database admin UIs ----
    (["pgadmin", "phpmyadmin", "adminer"], AppInfo(
        "Database admin UI", "Database management web UI", LEVEL_SERVER,
        "A web tool to manage a database, used directly by you. No VPN needed.",
        "Use your normal server IP.",
        "Database admin UIs let you browse and edit a database. They are internal tools, so they use your normal connection.")),
    # ---- databases ----
    (["postgres", "postgresql", "mariadb", "mysql", "mongo", "redis", "valkey"], AppInfo(
        "Database", "Database server (used by other apps)", LEVEL_SERVER,
        "A database that other containers talk to over your local network. It does not browse the internet, so no VPN.",
        "Use your normal server IP.",
        "Databases store data for your other apps and are reached over the internal Docker network. They do not make outbound internet trips that need hiding.")),
    # ---- transcoders ----
    (["tdarr", "unmanic", "handbrake"], AppInfo(
        "Media transcoder", "Transcodes / optimises your media", LEVEL_SERVER,
        "Processes your own media files locally. No VPN needed.",
        "Use your normal server IP.",
        "Transcoders convert your media to other formats on your own server. The work is local, so a VPN is not required.")),
    # ---- *arr companions / maintenance ----
    (["huntarr", "mediacleanuparr", "cleanuparr", "maintainerr", "recyclarr", "configarr", "checkrr"], AppInfo(
        "Media automation helper", "Maintenance for your *arr apps", LEVEL_OPTIONAL,
        "Talks to your *arr apps to tidy up or trigger searches. The risky downloads still happen in your download client, which is what must be on a VPN.",
        "Optional. Make sure your download client (and ideally your *arr apps) are on a VPN.",
        "These helpers automate housekeeping for Sonarr/Radarr etc - finding missing items, cleaning up, syncing settings. They mostly talk to your other apps locally, so a VPN is optional for them; the important thing is that the actual download client is protected.")),
]

_GENERIC = AppInfo(
    "Container", "Unrecognised app", LEVEL_UNKNOWN,
    "We don't have a specific recommendation for this app.",
    "If it downloads from public or peer-to-peer sources, consider a VPN. If it serves content to you or needs direct access, use your normal server IP.",
    "LeakWatch doesn't recognise this container, so it makes no assumption. As a rule of thumb: apps that fetch from public trackers, file hosts, or peers benefit from a VPN; apps that serve your own content or must be reachable directly should use your normal connection.")


def lookup(name: str, image: str = "") -> AppInfo:
    hay = (str(name) + " " + str(image)).lower()
    for keywords, info in CATALOG:
        for kw in keywords:
            if kw in hay:
                # Special case: a "*-vpn" torrent client is a client, not a pure gateway.
                if info.level == LEVEL_GATEWAY and any(t in hay for t in
                        ("deluge", "qbittorrent", "transmission", "torrent", "sabnzbd", "nzbget")):
                    return CATALOG[1][1]  # the torrent-client entry (critical)
                return info
    return _GENERIC
