import re
from urllib.parse import urlparse
from typing import List, Dict, Any

class AdvisoryFinder:
    """
    Intelligently aggregates, categorizes, and ranks authoritative references for a CVE,
    surfacing official NIST/MITRE records, vendor security bulletins, distribution errata,
    and elite threat research writeups while deduplicating entries.
    """
    
    VENDOR_DOMAINS = [
        "apache.org", "microsoft.com", "cisco.com", "redhat.com", "oracle.com",
        "paloaltonetworks.com", "apple.com", "google.com", "vmware.com", "debian.org",
        "ubuntu.com", "fortinet.com", "ivanti.com", "atlassian.com", "ibm.com",
        "juniper.net", "f5.com", "nginx.org", "jenkins.io", "gitlab.com", "github.com",
        "netapp.com", "broadcom.com", "sonicwall.com", "solarwinds.com", "dell.com",
        "hp.com", "hpe.com", "checkpoint.com", "trendmicro.com", "splunk.com"
    ]

    RESEARCH_DOMAINS = [
        "unit42.paloaltonetworks.com", "volexity.com", "bleepingcomputer.com",
        "rapid7.com", "tenable.com", "qualys.com", "sentinelone.com", "wiz.io",
        "huntress.com", "mandiant.com", "synacktiv.com", "zerodayinitiative.com",
        "packetstormsecurity.com", "openwall.com", "seclists.org", "sans.org",
        "isc.sans.edu", "cisa.gov", "cert.org", "kb.cert.org", "jvn.jp"
    ]

    def find_advisories(self, cve_id: str, references: List[str], vendor: str = "", product: str = "") -> List[Dict[str, Any]]:
        cve_clean = cve_id.upper().strip()
        seen_normalized = set()
        candidates = []

        # 1. Inject authoritative baseline standards (NIST NVD, MITRE, CISA)
        standards = [
            {
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_clean}",
                "title": f"NIST NVD Official Vulnerability Record ({cve_clean})",
                "badge": "NIST NVD DETAIL",
                "category": "standard",
                "domain": "nvd.nist.gov",
                "score": 100
            },
            {
                "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_clean}",
                "title": f"MITRE CVE Dictionary Official Specification",
                "badge": "MITRE CVE RECORD",
                "category": "standard",
                "domain": "cve.mitre.org",
                "score": 99
            },
            {
                "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve_clean}",
                "title": f"CISA Known Exploited Vulnerabilities (KEV) Catalog",
                "badge": "CISA KEV ALERT",
                "category": "standard",
                "domain": "cisa.gov",
                "score": 98
            }
        ]

        for std in standards:
            norm = self._normalize_url(std["url"])
            seen_normalized.add(norm)
            candidates.append(std)

        # 2. Process all NVD / vendor supplied references
        if references:
            for ref in references:
                if not ref or not isinstance(ref, str):
                    continue
                
                clean_ref = ref.strip()
                norm = self._normalize_url(clean_ref)
                if norm in seen_normalized:
                    continue
                seen_normalized.add(norm)

                parsed = urlparse(clean_ref)
                netloc = parsed.netloc.lower()
                path = parsed.path.lower()

                # Classify and score
                item = self._classify_reference(clean_ref, netloc, path, vendor, product, cve_clean)
                if item:
                    candidates.append(item)

        # Sort by priority score descending and limit to top 15
        candidates.sort(key=lambda x: x["score"], reverse=True)
        return candidates[:16]

    def _normalize_url(self, url: str) -> str:
        clean = re.sub(r"^https?://", "", url.lower())
        clean = re.sub(r"#.*$", "", clean)
        return clean.rstrip("/")

    def _classify_reference(self, url: str, netloc: str, path: str, vendor: str, product: str, cve_id: str) -> Dict[str, Any]:
        url_lower = url.lower()
        score = 50
        badge = "SECURITY BULLETIN"
        category = "general"
        title = ""

        clean_domain = netloc.replace("www.", "")

        # 1. Government / CERT alerts
        if "cisa.gov" in netloc:
            badge = "CISA KEV ALERT"
            category = "cisa"
            title = "CISA Cybersecurity Alert & Guidance"
            score = 97
        elif "kb.cert.org" in netloc or "cert.org" in netloc:
            badge = "CERT ADVISORY"
            category = "cert"
            title = "Carnegie Mellon CERT Vulnerability Note"
            score = 93
        elif "jvn.jp" in netloc:
            badge = "JVN ADVISORY"
            category = "cert"
            title = "Japan Vulnerability Notes Advisory"
            score = 88

        # 2. Zero Day Initiative (ZDI)
        elif "zerodayinitiative.com" in netloc:
            badge = "ZDI ADVISORY"
            category = "research"
            zdi_match = re.search(r"zdi-\d+-\d+", path)
            zdi_id = zdi_match.group(0).upper() if zdi_match else "Advisory"
            title = f"Zero Day Initiative {zdi_id} Technical Advisory"
            score = 91

        # 3. Red Hat Security Advisory / Errata
        elif "redhat.com" in netloc:
            if "errata" in path or "rhsa" in url_lower:
                rhsa_match = re.search(r"rhsa-\d+-\d+", url_lower)
                rhsa_str = f" ({rhsa_match.group(0).upper()})" if rhsa_match else ""
                badge = "VENDOR ERRATA"
                category = "vendor"
                title = f"Red Hat Security Advisory{rhsa_str}"
                score = 95
            else:
                badge = "VENDOR BULLETIN"
                category = "vendor"
                title = "Red Hat Security Bulletin"
                score = 84

        # 4. Debian & Ubuntu Linux Advisories
        elif "debian.org" in netloc:
            badge = "DEBIAN ADVISORY"
            category = "vendor"
            title = "Debian Security Advisory / LTS Bulletin"
            score = 90
        elif "ubuntu.com" in netloc:
            badge = "UBUNTU ADVISORY"
            category = "vendor"
            title = "Ubuntu Security Notice (USN)"
            score = 90

        # 5. OpenWall OSS-Security & Full Disclosure
        elif "openwall.com" in netloc:
            badge = "OSS-SECURITY"
            category = "research"
            title = "Openwall OSS-Security Public Disclosure"
            score = 86
        elif "seclists.org" in netloc:
            badge = "FULL DISCLOSURE"
            category = "research"
            title = "SecLists Full Disclosure Vulnerability Report"
            score = 85
        elif "packetstormsecurity.com" in netloc:
            badge = "PACKET STORM"
            category = "research"
            title = "Packet Storm Security Technical Bulletin"
            score = 82

        # 6. Specific Vendor Advisories
        elif any(vd in netloc for vd in self.VENDOR_DOMAINS) or (vendor and vendor.lower() in netloc):
            badge = "OFFICIAL VENDOR ADVISORY"
            category = "vendor"
            
            if "apache.org" in netloc:
                title = "Apache Official Security Announcement"
            elif "microsoft.com" in netloc:
                title = "Microsoft Security Response Center (MSRC) Advisory"
            elif "cisco.com" in netloc:
                title = "Cisco Security Advisory Bulletin"
            elif "oracle.com" in netloc:
                title = "Oracle Critical Patch Update Advisory"
            elif "paloaltonetworks.com" in netloc:
                title = "Palo Alto Networks Security Advisory"
            elif "vmware.com" in netloc:
                title = "VMware Security Advisory"
            elif "netapp.com" in netloc:
                title = "NetApp Product Security Advisory"
            elif "github.com/advisories" in url_lower:
                title = "GitHub Security Advisory Database"
            else:
                title = f"{clean_domain.capitalize()} Security Advisory"
            score = 94

        # 7. Elite Security Research Blogs & Threat Intelligence
        elif any(rd in netloc for rd in self.RESEARCH_DOMAINS):
            badge = "RESEARCH WRITEUP"
            category = "research"
            if "unit42" in netloc:
                title = "Palo Alto Networks Unit 42 Threat Analysis"
            elif "volexity.com" in netloc:
                title = "Volexity Threat Research & Zero-Day Incident Analysis"
            elif "trendmicro.com" in netloc:
                title = "Trend Micro Research Advisory"
            elif "rapid7.com" in netloc:
                title = "Rapid7 Threat Intelligence & Analysis"
            elif "bleepingcomputer.com" in netloc:
                title = "BleepingComputer Cybersecurity Report"
            elif "huntress.com" in netloc:
                title = "Huntress Threat Research & Detection Guide"
            elif "tenable.com" in netloc:
                title = "Tenable Security Response Advisory"
            elif "qualys.com" in netloc:
                title = "Qualys Threat Research Blog"
            else:
                title = f"{clean_domain.capitalize()} Threat Intelligence Bulletin"
            score = 89

        # 8. Source Code Patch Links
        elif "/commit/" in path or "/commits/" in path or "/pull/" in path:
            badge = "SOURCE PATCH"
            category = "patch"
            title = f"Upstream Source Code Patch ({clean_domain})"
            score = 87

        # 9. Generic Security Advisory / Bulletin paths
        elif any(k in path or k in url_lower for k in ["/advisory", "/security-bulletin", "/security-advisory", "/bulletin", "/alerts/"]):
            badge = "SECURITY BULLETIN"
            category = "vendor"
            title = f"{clean_domain.capitalize()} Security Bulletin"
            score = 78

        else:
            # Fallback for remaining useful links
            title = f"Security Reference ({clean_domain})"
            score = 60

        return {
            "url": url,
            "title": title,
            "badge": badge,
            "category": category,
            "domain": clean_domain,
            "score": score
        }
