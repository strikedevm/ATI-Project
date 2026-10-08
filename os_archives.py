# ==============================================================================
# Module: os_archives.py
# Description: Legacy OS Archival Intelligence & ISO Finder (Tier 3 Provisioning)
# Curates historical operating system images, official archive mirrors,
# and Virtual Machine hypervisor profiles for non-Docker / legacy kernel CVEs.
# ==============================================================================
import re
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("ai_engine")

class OSArchivesFinder:
    """
    Curated knowledge base and intelligent resolver for historical OS ISO images.
    When a CVE cannot run inside Docker or modern target machines (e.g. kernel exploits,
    legacy systemd/init dependencies, ancient glibc/OpenSSL versions), this engine
    identifies the exact operating system build, official archive mirror download URL,
    and recommended VM hypervisor parameters.
    """

    # Comprehensive Curated Registry of Historical OS Releases
    HISTORICAL_CATALOG = [
        # --- UBUNTU ARCHIVE (Canonical Official Old-Releases Mirror) ---
        {
            "id": "ubuntu-12-04",
            "name": "Ubuntu 12.04.5 LTS (Precise Pangolin)",
            "os_family": "linux",
            "distribution": "Ubuntu",
            "release_date": "2012-04-26",
            "eol_date": "2017-04-28",
            "kernel_version": "Linux 3.2.0 / 3.13.0",
            "architecture": "amd64 (x86_64)",
            "iso_url": "http://old-releases.ubuntu.com/releases/precise/ubuntu-12.04.5-server-amd64.iso",
            "mirror_portal": "http://old-releases.ubuntu.com/releases/precise/",
            "apt_sources_snippet": "deb http://old-releases.ubuntu.com/ubuntu/ precise main restricted universe multiverse\ndeb http://old-releases.ubuntu.com/ubuntu/ precise-security main restricted universe multiverse",
            "vm_profile": {"ram_mb": 1024, "vcpus": 1, "disk_gb": 20, "network": "Host-Only / NAT"},
            "tags": ["precise", "ubuntu 12", "kernel 3.2", "kernel 3.13", "ancient", "heartbleed", "shellshock"]
        },
        {
            "id": "ubuntu-14-04",
            "name": "Ubuntu 14.04.6 LTS (Trusty Tahr)",
            "os_family": "linux",
            "distribution": "Ubuntu",
            "release_date": "2014-04-17",
            "eol_date": "2019-04-25",
            "kernel_version": "Linux 3.13.0 / 4.4.0",
            "architecture": "amd64 (x86_64)",
            "iso_url": "http://old-releases.ubuntu.com/releases/trusty/ubuntu-14.04.6-server-amd64.iso",
            "mirror_portal": "http://old-releases.ubuntu.com/releases/trusty/",
            "apt_sources_snippet": "deb http://old-releases.ubuntu.com/ubuntu/ trusty main restricted universe multiverse\ndeb http://old-releases.ubuntu.com/ubuntu/ trusty-security main restricted universe multiverse",
            "vm_profile": {"ram_mb": 2048, "vcpus": 2, "disk_gb": 20, "network": "Host-Only / NAT"},
            "tags": ["trusty", "ubuntu 14", "kernel 3.13", "kernel 4.4", "dirty cow", "cve-2016-5195", "glibc"]
        },
        {
            "id": "ubuntu-16-04",
            "name": "Ubuntu 16.04.7 LTS (Xenial Xerus)",
            "os_family": "linux",
            "distribution": "Ubuntu",
            "release_date": "2016-04-21",
            "eol_date": "2021-04-30",
            "kernel_version": "Linux 4.4.0 / 4.15.0",
            "architecture": "amd64 (x86_64)",
            "iso_url": "http://old-releases.ubuntu.com/releases/xenial/ubuntu-16.04.7-server-amd64.iso",
            "mirror_portal": "http://old-releases.ubuntu.com/releases/xenial/",
            "apt_sources_snippet": "deb http://old-releases.ubuntu.com/ubuntu/ xenial main restricted universe multiverse\ndeb http://old-releases.ubuntu.com/ubuntu/ xenial-security main restricted universe multiverse",
            "vm_profile": {"ram_mb": 2048, "vcpus": 2, "disk_gb": 25, "network": "Host-Only / NAT"},
            "tags": ["xenial", "ubuntu 16", "kernel 4.4", "kernel 4.15", "overlayfs", "ebpf", "sudo"]
        },
        {
            "id": "ubuntu-18-04",
            "name": "Ubuntu 18.04.6 LTS (Bionic Beaver)",
            "os_family": "linux",
            "distribution": "Ubuntu",
            "release_date": "2018-04-26",
            "eol_date": "2023-05-31",
            "kernel_version": "Linux 4.15.0 / 5.4.0",
            "architecture": "amd64 (x86_64)",
            "iso_url": "http://old-releases.ubuntu.com/releases/bionic/ubuntu-18.04.6-live-server-amd64.iso",
            "mirror_portal": "http://old-releases.ubuntu.com/releases/bionic/",
            "apt_sources_snippet": "deb http://old-releases.ubuntu.com/ubuntu/ bionic main restricted universe multiverse\ndeb http://old-releases.ubuntu.com/ubuntu/ bionic-security main restricted universe multiverse",
            "vm_profile": {"ram_mb": 2048, "vcpus": 2, "disk_gb": 25, "network": "Host-Only / NAT"},
            "tags": ["bionic", "ubuntu 18", "kernel 4.15", "kernel 5.4", "polkit", "pwnkit", "cve-2021-4034"]
        },
        {
            "id": "ubuntu-20-04",
            "name": "Ubuntu 20.04.6 LTS (Focal Fossa)",
            "os_family": "linux",
            "distribution": "Ubuntu",
            "release_date": "2020-04-23",
            "eol_date": "2025-04-23",
            "kernel_version": "Linux 5.4.0 / 5.15.0",
            "architecture": "amd64 (x86_64)",
            "iso_url": "https://releases.ubuntu.com/focal/ubuntu-20.04.6-live-server-amd64.iso",
            "mirror_portal": "https://releases.ubuntu.com/focal/",
            "apt_sources_snippet": "deb http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse",
            "vm_profile": {"ram_mb": 4096, "vcpus": 2, "disk_gb": 30, "network": "Host-Only / NAT"},
            "tags": ["focal", "ubuntu 20", "kernel 5.4", "kernel 5.15", "log4shell", "spring4shell"]
        },

        # --- DEBIAN HISTORICAL ARCHIVE (Official Debian Archive) ---
        {
            "id": "debian-7",
            "name": "Debian 7.11 (Wheezy)",
            "os_family": "linux",
            "distribution": "Debian",
            "release_date": "2013-05-04",
            "eol_date": "2018-05-31",
            "kernel_version": "Linux 3.2.0",
            "architecture": "amd64 (x86_64)",
            "iso_url": "https://cdimage.debian.org/cdimage/archive/7.11.0/amd64/iso-cd/debian-7.11.0-amd64-netinst.iso",
            "mirror_portal": "https://archive.debian.org/debian-archive/debian/",
            "apt_sources_snippet": "deb http://archive.debian.org/debian/ wheezy main contrib non-free\necho 'Acquire::Check-Valid-Until \"false\";' > /etc/apt/apt.conf.d/99no-check",
            "vm_profile": {"ram_mb": 1024, "vcpus": 1, "disk_gb": 20, "network": "Host-Only / NAT"},
            "tags": ["wheezy", "debian 7", "kernel 3.2", "sysvinit", "legacy"]
        },
        {
            "id": "debian-8",
            "name": "Debian 8.11 (Jessie)",
            "os_family": "linux",
            "distribution": "Debian",
            "release_date": "2015-04-25",
            "eol_date": "2020-06-30",
            "kernel_version": "Linux 3.16.0",
            "architecture": "amd64 (x86_64)",
            "iso_url": "https://cdimage.debian.org/cdimage/archive/8.11.1/amd64/iso-cd/debian-8.11.1-amd64-netinst.iso",
            "mirror_portal": "https://archive.debian.org/debian-archive/debian/",
            "apt_sources_snippet": "deb http://archive.debian.org/debian/ jessie main contrib non-free\necho 'Acquire::Check-Valid-Until \"false\";' > /etc/apt/apt.conf.d/99no-check",
            "vm_profile": {"ram_mb": 1024, "vcpus": 1, "disk_gb": 20, "network": "Host-Only / NAT"},
            "tags": ["jessie", "debian 8", "kernel 3.16", "systemd", "dirty cow"]
        },
        {
            "id": "debian-9",
            "name": "Debian 9.13 (Stretch)",
            "os_family": "linux",
            "distribution": "Debian",
            "release_date": "2017-06-17",
            "eol_date": "2022-06-30",
            "kernel_version": "Linux 4.9.0",
            "architecture": "amd64 (x86_64)",
            "iso_url": "https://cdimage.debian.org/cdimage/archive/9.13.0/amd64/iso-cd/debian-9.13.0-amd64-netinst.iso",
            "mirror_portal": "https://archive.debian.org/debian-archive/debian/",
            "apt_sources_snippet": "deb http://archive.debian.org/debian/ stretch main contrib non-free\necho 'Acquire::Check-Valid-Until \"false\";' > /etc/apt/apt.conf.d/99no-check",
            "vm_profile": {"ram_mb": 2048, "vcpus": 1, "disk_gb": 20, "network": "Host-Only / NAT"},
            "tags": ["stretch", "debian 9", "kernel 4.9", "exim", "samba"]
        },
        {
            "id": "debian-10",
            "name": "Debian 10.13 (Buster)",
            "os_family": "linux",
            "distribution": "Debian",
            "release_date": "2019-07-06",
            "eol_date": "2024-06-30",
            "kernel_version": "Linux 4.19.0",
            "architecture": "amd64 (x86_64)",
            "iso_url": "https://cdimage.debian.org/cdimage/archive/10.13.0/amd64/iso-cd/debian-10.13.0-amd64-netinst.iso",
            "mirror_portal": "https://archive.debian.org/debian-archive/debian/",
            "apt_sources_snippet": "deb http://archive.debian.org/debian/ buster main contrib non-free",
            "vm_profile": {"ram_mb": 2048, "vcpus": 2, "disk_gb": 20, "network": "Host-Only / NAT"},
            "tags": ["buster", "debian 10", "kernel 4.19", "polkit", "openssh"]
        },

        # --- CENTOS VAULT ARCHIVE ---
        {
            "id": "centos-6",
            "name": "CentOS 6.10",
            "os_family": "linux",
            "distribution": "CentOS",
            "release_date": "2018-07-03",
            "eol_date": "2020-11-30",
            "kernel_version": "Linux 2.6.32",
            "architecture": "x86_64",
            "iso_url": "https://vault.centos.org/6.10/isos/x86_64/CentOS-6.10-x86_64-bin-DVD1.iso",
            "mirror_portal": "https://vault.centos.org/6.10/",
            "apt_sources_snippet": "sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-* && sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*",
            "vm_profile": {"ram_mb": 2048, "vcpus": 1, "disk_gb": 25, "network": "Host-Only / NAT"},
            "tags": ["centos 6", "rhel 6", "kernel 2.6.32", "rpm", "yum", "ghost", "cve-2015-0235"]
        },
        {
            "id": "centos-7",
            "name": "CentOS 7.9.2009",
            "os_family": "linux",
            "distribution": "CentOS",
            "release_date": "2020-11-12",
            "eol_date": "2024-06-30",
            "kernel_version": "Linux 3.10.0",
            "architecture": "x86_64",
            "iso_url": "https://vault.centos.org/7.9.2009/isos/x86_64/CentOS-7-x86_64-Minimal-2009.iso",
            "mirror_portal": "https://vault.centos.org/7.9.2009/",
            "apt_sources_snippet": "sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-* && sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*",
            "vm_profile": {"ram_mb": 2048, "vcpus": 2, "disk_gb": 25, "network": "Host-Only / NAT"},
            "tags": ["centos 7", "rhel 7", "kernel 3.10", "systemd", "cve-2021-3156", "sudo baron samedit"]
        },

        # --- WINDOWS SERVER EVALUATION & HERITAGE ARCHIVES ---
        {
            "id": "win-server-2008-r2",
            "name": "Windows Server 2008 R2 SP1",
            "os_family": "windows",
            "distribution": "Microsoft Windows Server",
            "release_date": "2009-10-22",
            "eol_date": "2020-01-14",
            "kernel_version": "NT 6.1.7601",
            "architecture": "x64",
            "iso_url": "https://archive.org/download/windowsserver2008r2sp1x64/en_windows_server_2008_r2_with_sp1_x64_dvd_617601.iso",
            "mirror_portal": "https://archive.org/details/windowsserver2008r2sp1x64",
            "apt_sources_snippet": "# Windows Update Catalog offline cab patching required.",
            "vm_profile": {"ram_mb": 2048, "vcpus": 2, "disk_gb": 40, "network": "Host-Only / Isolated"},
            "tags": ["windows server 2008", "ms17-010", "eternalblue", "cve-2017-0144", "smbv1", "bluekeep", "cve-2019-0708"]
        },
        {
            "id": "win-server-2012-r2",
            "name": "Windows Server 2012 R2 Evaluation",
            "os_family": "windows",
            "distribution": "Microsoft Windows Server",
            "release_date": "2013-10-18",
            "eol_date": "2023-10-10",
            "kernel_version": "NT 6.3.9600",
            "architecture": "x64",
            "iso_url": "https://software-download.microsoft.com/download/pr/Windows_Server_2012_R2_Datacenter_Evaluation_EN-US.ISO",
            "mirror_portal": "https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2012-r2",
            "apt_sources_snippet": "# Windows Server 2012 R2 evaluation ISO from Microsoft Eval Center.",
            "vm_profile": {"ram_mb": 4096, "vcpus": 2, "disk_gb": 50, "network": "Host-Only / Isolated"},
            "tags": ["windows server 2012", "zerologon", "cve-2020-1472", "printnightmare", "cve-2021-34527", "active directory"]
        },
        {
            "id": "win-server-2016",
            "name": "Windows Server 2016 Evaluation",
            "os_family": "windows",
            "distribution": "Microsoft Windows Server",
            "release_date": "2016-10-15",
            "eol_date": "2027-01-12",
            "kernel_version": "NT 10.0.14393",
            "architecture": "x64",
            "iso_url": "https://software-download.microsoft.com/download/pr/Windows_Server_2016_Datacenter_Evaluation_EN-US.ISO",
            "mirror_portal": "https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2016",
            "apt_sources_snippet": "# Official Microsoft Evaluation Center ISO.",
            "vm_profile": {"ram_mb": 4096, "vcpus": 2, "disk_gb": 60, "network": "Host-Only / Isolated"},
            "tags": ["windows server 2016", "cve-2021-34527", "printnightmare", "cve-2022-26923", "activedirectory"]
        },
        {
            "id": "win-server-2019",
            "name": "Windows Server 2019 Evaluation",
            "os_family": "windows",
            "distribution": "Microsoft Windows Server",
            "release_date": "2018-10-02",
            "eol_date": "2029-01-09",
            "kernel_version": "NT 10.0.17763",
            "architecture": "x64",
            "iso_url": "https://software-download.microsoft.com/download/pr/17763.737.190906-2324.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us_1.iso",
            "mirror_portal": "https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019",
            "apt_sources_snippet": "# Official Microsoft Evaluation Center ISO.",
            "vm_profile": {"ram_mb": 4096, "vcpus": 2, "disk_gb": 60, "network": "Host-Only / Isolated"},
            "tags": ["windows server 2019", "follina", "cve-2022-30190", "zerologon", "cve-2020-1472"]
        }
    ]

    def __init__(self):
        pass

    def match_legacy_os(self, cve_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyzes CVE metadata, description, and affected components to recommend
        historical OS ISO images when containerized builds cannot fulfill kernel/OS requirements.
        """
        cve_id = cve_data.get("cve_id", "").upper()
        description = (cve_data.get("description", "") or "").lower()
        affected = str(cve_data.get("affected_products", "") or "").lower()
        combined_text = f"{cve_id} {description} {affected}"

        matches = []
        for entry in self.HISTORICAL_CATALOG:
            score = 0
            reasons = []

            # 1. Exact Tag Matches
            for tag in entry["tags"]:
                if tag.lower() in combined_text:
                    score += 3
                    reasons.append(f"Matched keyword: '{tag}'")

            # 2. Kernel Version Pattern Heuristics
            if entry["os_family"] == "linux":
                # Check for explicit kernel references
                if "kernel" in combined_text or "linux" in combined_text:
                    if "3." in entry["kernel_version"] and any(k in combined_text for k in ["3.", "kernel 3", "2.6", "before 4."]):
                        score += 4
                        reasons.append(f"Matching Linux kernel branch: {entry['kernel_version']}")
                    elif "4.4" in entry["kernel_version"] and any(k in combined_text for k in ["4.4", "before 4.5", "kernel 4"]):
                        score += 3
                        reasons.append(f"Matching LTS kernel branch: {entry['kernel_version']}")

            # 3. Windows Specific Checks
            if entry["os_family"] == "windows":
                if any(w in combined_text for w in ["windows", "microsoft", "smb", "rdp", "active directory", "ntlm", "kerberos"]):
                    score += 2
                    if entry["id"] == "win-server-2008-r2" and any(k in combined_text for k in ["eternalblue", "ms17-010", "bluekeep", "0144", "0708"]):
                        score += 8
                        reasons.append("Exact CVE match: EternalBlue / BlueKeep target")
                    elif entry["id"] == "win-server-2012-r2" and any(k in combined_text for k in ["zerologon", "1472", "printnightmare"]):
                        score += 8
                        reasons.append("Exact CVE match: ZeroLogon / PrintNightmare target")

            if score > 0:
                match_item = dict(entry)
                match_item["match_score"] = score
                match_item["match_reasons"] = list(set(reasons))
                matches.append(match_item)

        # Sort matches by score descending
        matches.sort(key=lambda x: x["match_score"], reverse=True)

        # If no specific matches, return top baseline LTS images (Ubuntu 18.04, Debian 10, CentOS 7, Windows 2016)
        if not matches:
            fallback_ids = ["ubuntu-18-04", "debian-10", "centos-7", "win-server-2016"]
            for entry in self.HISTORICAL_CATALOG:
                if entry["id"] in fallback_ids:
                    fallback_item = dict(entry)
                    fallback_item["match_score"] = 1
                    fallback_item["match_reasons"] = ["Standard Baseline Sandbox (General Compatibility)"]
                    matches.append(fallback_item)

        return matches

    def search_catalog(self, query: str = "") -> List[Dict[str, Any]]:
        """Searches historical catalog by distribution, release name, kernel, or tag."""
        if not query:
            return self.HISTORICAL_CATALOG

        q = query.lower().strip()
        results = []
        for entry in self.HISTORICAL_CATALOG:
            searchable = (
                f"{entry['name']} {entry['distribution']} {entry['kernel_version']} "
                f"{entry['architecture']} {' '.join(entry['tags'])}"
            ).lower()
            if q in searchable:
                results.append(entry)
        return results

    def get_setup_instructions(self, os_id: str) -> Dict[str, str]:
        """Provides quick copy-paste hypervisor setup instructions."""
        entry = next((item for item in self.HISTORICAL_CATALOG if item["id"] == os_id), None)
        if not entry:
            return {}

        vm = entry["vm_profile"]
        return {
            "virtualbox": (
                f"1. Download ISO: {entry['iso_url']}\n"
                f"2. Create VM -> Type: {entry['os_family'].capitalize()} -> Version: {entry['distribution']}\n"
                f"3. Base Memory: {vm['ram_mb']} MB | Processors: {vm['vcpus']} vCPU\n"
                f"4. Hard Disk: {vm['disk_gb']} GB (VDI dynamic)\n"
                f"5. Network: Host-Only Adapter (Protects host while allowing isolated pentesting)"
            ),
            "vmware": (
                f"1. New Virtual Machine -> Custom (Advanced)\n"
                f"2. Installer disc image: {entry['iso_url']}\n"
                f"3. Memory: {vm['ram_mb']} MB | CPU Cores: {vm['vcpus']}\n"
                f"4. Disk: {vm['disk_gb']} GB\n"
                f"5. Network Connection: Host-Only (VMnet1) for strict containment"
            )
        }

# Global singleton
os_archives = OSArchivesFinder()
