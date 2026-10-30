// @ts-check

const CUSTOM_ACTION_APPCACHE_REMOVE = "appcache-remove";

/**
 * @typedef {Object} PayloadInfo
 * @property {string} displayTitle
 * @property {string} description
 * @property {string} fileName - path relative to the payloads folder
 * @property {string} author
 * @property {string} projectSource
 * @property {string} binarySource - should be direct download link to the included version, so that you can verify the hashes
 * @property {string} version
 * @property {string[]?} [supportedFirmwares] - optional, these are interpreted as prefixes, so "" would match all, and "4." would match 4.xx, if not set, the payload is assumed to be compatible with all firmwares
 * @property {number?} [toPort] - optional, if the payload should be sent to "127.0.0.1:<port>" instead of loading directly, if specified it'll show up in webkit-only mode too
 * @property {string?} [customAction]
 */

/**
 * @type {PayloadInfo[]}
*/
const payload_map = [
    {
        displayTitle: "Install ProsperoStore",
        description: "Downloads and installs the latest ProsperoStore homebrew app to /data/homebrew/.",
        fileName: "install-prospero-store.elf",
        author: "darkxex",
        projectSource: "https://github.com/darkxex/ProsperoStore",
        binarySource: "https://git.etawen.dev/earthonion/install-prospero-store/releases/download/v1.0/install-prospero-store.elf",
        version: "1.0",
        toPort: 9021
    },
    {
        displayTitle: "kstuff-lite",
        description: "FPKG enabler (v1.11, FW 1.00-13.60).",
        fileName: "kstuff-lite.elf",
        author: "sleirsgoevy, john-tornblom, EchoStretch, buzzer-re, idlesauce, BestPig, LightningMods, zecoxao, drakmor",
        projectSource: "https://github.com/EchoStretch/kstuff-lite",
        binarySource: "https://github.com/EchoStretch/kstuff-lite/releases/download/v1.11/kstuff.elf",
        version: "1.11",
        supportedFirmwares: ["1.", "2.", "3.", "4.", "5.", "6.", "7.", "8.", "9.", "10.", "11.", "12.", "13."],
        toPort: 9021
    },
    {
        displayTitle: "ShadowMountPlus",
        description: "Automated background auto-mounter for game dumps from internal + external storage. Run after etaHEN (has kstuff built in).",
        fileName: "shadowmountplus.elf",
        author: "drakmor",
        projectSource: "https://github.com/drakmor/ShadowMountPlus",
        binarySource: "https://github.com/drakmor/ShadowMountPlus/releases/download/1.7beta11/shadowmountplus.elf",
        version: "1.7beta11",
        supportedFirmwares: ["3.", "4.", "5.", "7.", "8.", "9.", "10.", "11.", "12.", "13."],
        toPort: 9021
    },
    {
        displayTitle: "PS5 Linux Loader (13.60)",
        description: "Boot into Linux on the PS5 Pro — soniciso1's ps5-linux-loader for firmware 13.60. Version v13.60.",
        fileName: "ps5-linux-loader-13.60.elf",
        author: "soniciso1",
        projectSource: "https://github.com/soniciso1/ps5-linux-loader",
        binarySource: "https://github.com/soniciso1/ps5-linux-loader/releases/download/10.xx-support/ps5-linux-loader-10-13-20261025.elf",
        version: "10.xx-support",
        supportedFirmwares: ["13.60"],
        toPort: 9021
    },
    {
        displayTitle: "CheatRunner",
        description: "Web-based game cheat trainer. Version v0.17.1.",
        fileName: "CheatRunner_v0.17.1.elf",
        author: "notmaj0r",
        projectSource: "https://github.com/notmaj0r/CheatRunner",
        binarySource: "https://github.com/notmaj0r/CheatRunner/releases/download/v0.18/CheatRunner.elf",
        version: "0.18",
        toPort: 9021
    },
    {
        displayTitle: "Lapy-JB-Daemon",
        description: "Standalone homebrew jailbreak daemon. Version v1.2.",
        fileName: "Lapy-JB-Daemon_v1.2.elf",
        author: "Lapy",
        projectSource: "https://github.com/Lapy-JB-Daemon",
        binarySource: "https://soniciso1.github.io/relapse/payloads/Lapy-JB-Daemon_v1.2.elf",
        version: "1.2",
        toPort: 9021
    },
    {
        displayTitle: "PKG-Manager",
        description: "Browse and install PKGs from USB, disc, or SMB shares directly on the console. Version v1.4.1.",
        fileName: "PKG-Manager_v1.4.1.elf",
        author: "itsPLK",
        projectSource: "https://github.com/itsPLK/ps5-pkg-manager",
        binarySource: "https://github.com/itsPLK/ps5-pkg-manager/releases/download/v1.5.1/pkg-manager_v1.5.1.elf",
        version: "1.5.1",
        toPort: 9021
    },
    {
        displayTitle: "ftpsrv-drakmor",
        description: "drakmor's fork of ftpsrv. Version 1.16-ng-stable.",
        fileName: "ftpsrv-drakmor_1.16-ng-stable.elf",
        author: "drakmor",
        projectSource: "https://github.com/drakmor/ftpsrv",
        binarySource: "https://soniciso1.github.io/relapse/payloads/ftpsrv-drakmor_1.16-ng-stable.elf",
        version: "1.16-ng-stable",
        toPort: 9021
    },
    {
        displayTitle: "ps5debug-NG",
        description: "PS5 debugger payload with a userland TCP wire-protocol server. Version 1.3.2.",
        fileName: "ps5debug-NG_1.3.2.elf",
        author: "Pharaoh2k",
        projectSource: "https://github.com/Pharaoh2k/ps5debug-ng",
        binarySource: "https://soniciso1.github.io/relapse/payloads/ps5debug-NG_1.3.2.elf",
        version: "1.3.2",
        toPort: 9021
    },
    {
        displayTitle: "zftpd",
        description: "Zero-copy FTP/HTTP server. Version v1.6.0.",
        fileName: "zftpd_v1.6.0.elf",
        author: "seregonwar",
        projectSource: "https://github.com/seregonwar/zftpd",
        binarySource: "https://soniciso1.github.io/relapse/payloads/zftpd_v1.6.0.elf",
        version: "1.6.0",
        toPort: 9021
    },
    {
        displayTitle: "PS5 HEN (cragson)",
        description: "Homebrew Enabler for PS5 firmware 1.00-4.51 (HV exploit chain, dev-latest build).",
        fileName: "ps5-hen.elf",
        author: "cragson",
        projectSource: "https://github.com/cragson/ps5-hen",
        binarySource: "https://github.com/cragson/ps5-hen/releases/download/dev-latest/ps5-hen.elf",
        version: "dev-latest",
        supportedFirmwares: ["1.", "2.", "3.", "4."],
        toPort: 9021
    },
    {
        displayTitle: "PS5 Payload Manager",
        description: "Web-based dashboard to manage, import, and auto-load payloads. Pair with a Y2JB/BD-JB/Lua autoloader.",
        fileName: "pldmgr.elf",
        author: "itsPLK",
        projectSource: "https://github.com/itsPLK/ps5-payload-manager",
        binarySource: "https://github.com/itsPLK/ps5-payload-manager/releases/download/v0.6.3/pldmgr_v0.6.3.elf",
        version: "0.6.3",
        toPort: 9021
    },
    {
        displayTitle: "PS5 Linux Loader",
        description: "Boots into Linux. Requires a linux-image on a USB drive or M.2 SSD. Reboot to return to PS5 UI.",
        fileName: "ps5-linux-loader.elf",
        author: "TheFl0w, c0w-ar",
        projectSource: "https://github.com/ps5-linux/ps5-linux-loader",
        binarySource: "https://github.com/ps5-linux/ps5-linux-loader/releases/download/v2.5/ps5-linux-loader.elf",
        version: "2.5",
        supportedFirmwares: ["3.", "4.", "5."],
        toPort: 9021
    },
    {
        displayTitle: "Garlic Savemgr",
        description: "Local PS5 save manager.",
        fileName: "garlic-savemgr.elf",
        author: "earthonion",
        projectSource: "https://git.etawen.dev/earthonion/garlic-savemgr",
        binarySource: "https://git.etawen.dev/earthonion/garlic-savemgr/releases/download/v1.14/garlic-savemgr.elf",
        version: "1.14",
        supportedFirmwares: ["3.", "4.", "5.", "7.", "8.", "9.", "10.", "11.", "12.", "13."],
        toPort: 9021
    },
    {
        displayTitle: "Elf Arsenal",
        description: "All-in-one PS5 utility.",
        fileName: "elf-arsenal.elf",
        author: "sonic-iso",
        projectSource: "https://git.etawen.dev/soniciso/elf-arsenal",
        binarySource: "https://git.etawen.dev/soniciso/elf-arsenal/releases/download/v1.6.23/elf-arsenal.elf",
        version: "1.6.23",
        supportedFirmwares: ["3.", "4.", "5.", "7.", "8.", "9.", "10.", "11.", "12.", "13."],
        toPort: 9021
    },
    // { // auto-loaded
    //     displayTitle: "PS5 Payload ELF Loader",
    //     description: "Uses port 9021. Persistent network elf loader",
    //     fileName: "elfldr-ps5.elf",
    //     author: "john-tornblom",
    //     projectSource: "https://github.com/ps5-payload-dev/elfldr",
    //     binarySource: "https://github.com/ps5-payload-dev/elfldr/releases/tag/v0.21",
    //     version: "0.21",
    //     supportedFirmwares: ["1.", "2.", "3.", "4.", "5."]
    // },
    {
        displayTitle: "etaHEN 2.5B (legacy)",
        description: "AIO HEN, older stable build for FW 3.00-5.50.",
        fileName: "etaHEN-2.5B.bin",
        author: "LightningMods, Buzzer, sleirsgoevy, ChendoChap, astrelsky, illusion, CTN, SiSTR0, Nomadic",
        projectSource: "https://github.com/etaHEN/etaHEN",
        binarySource: "https://github.com/etaHEN/etaHEN/releases/download/2.5B/etaHEN-2.5B.bin",
        version: "2.5B",
        supportedFirmwares: ["3.", "4.", "5."],
        toPort: 9021
    },
    {
        displayTitle: "etaHEN",
        description: "AIO HEN with kstuff built in (GronedWaffel unified build, FW 11.00-13.60).",
        fileName: "etaHEN.elf",
        author: "LightningMods, Buzzer, sleirsgoevy, ChendoChap, astrelsky, illusion, CTN, SiSTR0, Nomadic, GronedWaffel",
        projectSource: "https://github.com/GronedWaffel/etahen-11.00-13.60",
        binarySource: "https://github.com/GronedWaffel/etahen-11.00-13.60/releases/download/v2.5B-unified.1/etaHEN-11.00-13.60.elf",
        version: "2.5B-unified.1",
        toPort: 9021
    },
    {
        displayTitle: "OnionHEN",
        description: "HEN + Toolbox: injects ShellUI overlays, cheats, and background services.",
        fileName: "onionhen.elf",
        author: "aydencharles",
        projectSource: "https://github.com/aydencharles/onionHEN",
        binarySource: "https://github.com/aydencharles/onionHEN/releases/download/v0.9.0/OnionHEN.elf",
        version: "0.9.0",
        toPort: 9021
    },
    {
        displayTitle: "Byepervisor HEN",
        description: "FPKG enabler",
        fileName: "byepervisor.elf",
        author: "SpecterDev, ChendoChap, flatz, fail0verflow, Znullptr, kiwidog, sleirsgoevy, EchoStretch, LightningMods, BestPig, zecoxao, TheOfficialFloW",
        projectSource: "https://github.com/EchoStretch/Byepervisor",
        binarySource: "https://github.com/EchoStretch/Byepervisor/releases/download/1.1/byepervisor.elf",
        version: "1.1",
        supportedFirmwares: ["1.00", "1.01", "1.02", "1.12", "1.14", "2.00", "2.20", "2.25", "2.26", "2.30", "2.50", "2.70"],
        toPort: 9021
    },
    {
        displayTitle: "Byepervisor Reborn",
        description: "HV exploit for 6.xx-13.60. Disables XOM, enables kernel R/W. Developer tool — rest mode required.",
        fileName: "byepervisor_reborn.elf",
        author: "PS5Dev, theflow0, soniciso1, ChendoChap",
        projectSource: "https://github.com/PS5Dev/Byepervisor-Reborn",
        binarySource: "https://github.com/PS5Dev/Byepervisor-Reborn",
        version: "1.0",
        supportedFirmwares: ["6.", "7.", "8.", "9.", "10.", "11.", "12.", "13."],
        toPort: 9021
    },
    {
        displayTitle: "libhijacker game-patch",
        description: "Patches supported games to run at higher framerates, and adds debug menus to certain titles.",
        fileName: "libhijacker-game-patch.v1.160.elf",
        author: "illusion0001, astrelsky",
        projectSource: "https://github.com/illusion0001/libhijacker",
        binarySource: "https://github.com/illusion0001/libhijacker-game-patch/releases/tag/1.160-75ab26a3",
        version: "1.160",
        supportedFirmwares: ["3.", "4."]
    },
    {
        displayTitle: "websrv",
        description: "Custom homebrew loader. Runs on port 8080.",
        fileName: "websrv-ps5.elf",
        author: "john-tornblom",
        projectSource: "https://github.com/ps5-payload-dev/websrv",
        binarySource: "https://github.com/ps5-payload-dev/websrv/releases/download/v0.34/websrv-ps5.elf",
        version: "0.34",
        toPort: 9021
    },
    {
        displayTitle: "ftpsrv",
        description: "FTP server. Runs on port 2121.",
        fileName: "ftpsrv-ps5.elf",
        author: "john-tornblom",
        projectSource: "https://github.com/ps5-payload-dev/ftpsrv",
        binarySource: "https://github.com/ps5-payload-dev/ftpsrv/releases/download/v0.21.1/ftpsrv-ps5.elf",
        version: "0.21.1",
        toPort: 9021
    },
    {
        displayTitle: "klogsrv",
        description: "Klog server. Runs on port 3232.",
        fileName: "klogsrv-ps5.elf",
        author: "john-tornblom",
        projectSource: "https://github.com/ps5-payload-dev/klogsrv",
        binarySource: "https://github.com/ps5-payload-dev/klogsrv/releases/download/v0.9/klogsrv-ps5.elf",
        version: "0.9",
        toPort: 9021
    },
    {
        displayTitle: "shsrv",
        description: "Telnet shell server. Runs on port 2323.",
        fileName: "shsrv-ps5.elf",
        author: "john-tornblom",
        projectSource: "https://github.com/ps5-payload-dev/shsrv",
        binarySource: "https://github.com/ps5-payload-dev/shsrv/releases/download/v0.20/shsrv-ps5.elf",
        version: "0.20",
        toPort: 9021
    },
    {
        displayTitle: "gdbsrv",
        description: "GDB server. Runs on port 2159.",
        fileName: "gdbsrv-ps5.elf",
        author: "john-tornblom",
        projectSource: "https://github.com/ps5-payload-dev/gdbsrv",
        binarySource: "https://github.com/ps5-payload-dev/gdbsrv/releases/download/v0.9/gdbsrv-ps5.elf",
        version: "0.9",
        toPort: 9021
    },
    {
        displayTitle: "ps5debug",
        description: "Debugger",
        fileName: "ps5debug_v1.0b5.elf",
        author: "SiSTR0, ctn123",
        projectSource: "https://github.com/GoldHEN/ps5debug",
        binarySource: "https://github.com/GoldHEN/ps5debug/releases/download/1.0b5/ps5debug_v1.0b5.elf",
        version: "1.0b5",
        supportedFirmwares: ["3.", "4.", "5."],
        toPort: 9021
    },
    {
        displayTitle: "ps5debug",
        description: "Debugger, open source version by DizzRL",
        fileName: "ps5debug_dizz.elf",
        author: "Dizz, astrelsky, John Tornblom, SiSTR0, golden, idlesauce",
        projectSource: "https://github.com/idlesauce/ps5debug",
        binarySource: "https://github.com/idlesauce/ps5debug/releases/download/v0.0.1/ps5debug.elf",
        version: "0.0.1-r2",
        toPort: 9021
    },
    {
        displayTitle: "ps5-versions",
        description: "Shows kernel build, os and sdk versions",
        fileName: "ps5-versions.elf",
        author: "SiSTRo",
        projectSource: "https://github.com/SiSTR0/ps5-versions",
        binarySource: "https://github.com/SiSTR0/ps5-versions/releases/download/v1.0/ps5-versions.elf",
        version: "1.0",
        supportedFirmwares: ["1.", "2.", "3.", "4."]
    },
    {
        displayTitle: "ps5-remoteplay-get-pin",
        description: "Get Remote Play PIN for offline activated users. Send again to cancel.",
        fileName: "rp-get-pin.elf",
        author: "idlesauce",
        projectSource: "https://github.com/idlesauce/ps5-remoteplay-get-pin",
        binarySource: "https://github.com/idlesauce/ps5-remoteplay-get-pin/releases/tag/v0.1.1",
        version: "0.1.1",
        toPort: 9021
    },
    {
        // https://github.com/Storm21CH/PS5_Browser_appCache_remove
        displayTitle: "Browser appcache remover",
        description: "Deletes for only the current user in webkit-only mode",
        fileName: "",
        author: "Storm21CH, idlesauce",
        projectSource: "",
        binarySource: "",
        version: "1.0",
        customAction: CUSTOM_ACTION_APPCACHE_REMOVE
    },
    {
        displayTitle: "PoorDS4",
        description: "Use a wireless DualShock 4 in native PS5 games on jailbroken consoles.",
        fileName: "PoorDS4rc51.elf",
        author: "ItsBlurf",
        projectSource: "https://github.com/ItsBlurf/PoorDS4",
        binarySource: "https://github.com/ItsBlurf/PoorDS4/releases/download/v0.1.0-rc51/PoorDS4rc51.elf",
        version: "0.1.0-rc51",
        toPort: 9021
    },
    {
        displayTitle: "PoorDS4 Status",
        description: "Show the PoorDS4 daemon status.",
        fileName: "PoorDS4-status.elf",
        author: "ItsBlurf",
        projectSource: "https://github.com/ItsBlurf/PoorDS4",
        binarySource: "https://github.com/ItsBlurf/PoorDS4/releases/download/v0.2.0/PoorDS4-status.elf",
        version: "0.2.0",
        toPort: 9021
    },
    {
        displayTitle: "PoorDS4 Stop",
        description: "Stop the PoorDS4 daemon.",
        fileName: "PoorDS4-stop.elf",
        author: "ItsBlurf",
        projectSource: "https://github.com/ItsBlurf/PoorDS4",
        binarySource: "https://github.com/ItsBlurf/PoorDS4/releases/download/v0.2.0/PoorDS4-stop.elf",
        version: "0.2.0",
        toPort: 9021
    },
    {
        displayTitle: "PS5Upload",
        description: "Console-side daemon for PS5Upload — send apps/homebrew from the PC or phone app without slow transfers.",
        fileName: "ps5upload_v5.41.0.elf",
        author: "phantomptr",
        projectSource: "https://github.com/phantomptr/ps5upload",
        binarySource: "https://github.com/phantomptr/ps5upload/releases/download/v9.3.0/ps5upload-9.3.0.elf",
        version: "9.3.0",
        toPort: 9021
    },
    {
        displayTitle: "PS5 App Dumper",
        description: "Dump installed apps and games to USB storage.",
        fileName: "ps5-app-dumper_v2.00.elf",
        author: "EchoStretch",
        projectSource: "https://github.com/EchoStretch/ps5-app-dumper",
        binarySource: "https://github.com/EchoStretch/ps5-app-dumper/releases/download/v2.10/ps5-app-dumper_v2.10.elf",
        version: "2.10",
        toPort: 9021
    },
    {
        displayTitle: "Payload Host Installer",
        description: "Installs a home screen shortcut that jailbreaks and opens the payload menu.",
        fileName: "payloadhost-install.elf",
        author: "earthonion",
        projectSource: "https://github.com/earthonion/np-fake-signin",
        binarySource: "https://satanic.lol/payloads/payloads/payloadhost-install.elf",
        version: "1.0",
        toPort: 9021
    },
    {
        displayTitle: "Relapse Installer",
        description: "Installs the Relapse app on your home screen (one-time).",
        fileName: "relapse-install.elf",
        author: "earthonion",
        projectSource: "https://github.com/earthonion/np-fake-signin",
        binarySource: "https://satanic.lol/relapse/payloads/relapse-install.elf",
        version: "1.0",
        toPort: 9021
    },
    {
        displayTitle: "Relapse Installer (Direct)",
        description: "Installs Relapse on your home screen — launches the exploit directly, no menu.",
        fileName: "relapse-direct-install.elf",
        author: "earthonion",
        projectSource: "https://github.com/earthonion/np-fake-signin",
        binarySource: "https://satanic.lol/payloads/payloads/relapse-direct-install.elf",
        version: "1.0",
        toPort: 9021
    },
    {
        displayTitle: "poopicker Installer",
        description: "Installs the poopicker app on your home screen (one-time).",
        fileName: "poopicker-install.elf",
        author: "soniciso1",
        projectSource: "https://github.com/soniciso1/poopicker",
        binarySource: "https://satanic.lol/payloads/payloads/poopicker-install.elf",
        version: "1.0",
        toPort: 9021
    },
    {
        displayTitle: "dr.yenyen Installer",
        description: "Installs the dr.yenyen app on your home screen (one-time).",
        fileName: "yenyen-install.elf",
        author: "earthonion",
        projectSource: "https://github.com/earthonion/np-fake-signin",
        binarySource: "https://satanic.lol/payloads/payloads/yenyen-install.elf",
        version: "1.0",
        toPort: 9021
    },
    {
        displayTitle: "WebKit Autoloader Installer",
        description: "Installs a WebKit-based payload autoloader onto the console (by itsPLK).",
        fileName: "webkit-autoloader-installer.elf",
        author: "itsPLK",
        projectSource: "https://github.com/itsPLK/ps5-webkit-autoloader",
        binarySource: "https://github.com/itsPLK/ps5-webkit-autoloader/releases/download/v0.6.2/webkit-autoloader-installer_v0.6.2.elf",
        version: "0.6.2",
        toPort: 9021
    },
];
