import requests
import time

SOURCE_MAPPINGS = {
    "134c704f-9b21-4f2e-91b3-4a467353bcc0": "CISA-ADP",
    "nvd@nist.gov": "NIST: NVD",
    "cve@mitre.org": "MITRE",
}

class CVECollector:
    def __init__(self):
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self._kev_cache = None
        # Enhanced headers to bypass NVD automated bot blocking
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json"
        }

    def _get_cisa_kev_list(self):
        if self._kev_cache is not None:
            return self._kev_cache
        try:
            res = requests.get(self.cisa_kev_url, headers=self.headers, timeout=8)
            if res.status_code == 200:
                vulnerabilities = res.json().get("vulnerabilities", [])
                self._kev_cache = {v.get("cveID", "").upper() for v in vulnerabilities}
                return self._kev_cache
        except Exception as e:
            print(f"[!] Warning: Unable to fetch CISA KEV list: {e}")
        self._kev_cache = set()
        return self._kev_cache

    def _format_source(self, raw_source):
        if not raw_source:
            return "N/A"
        return SOURCE_MAPPINGS.get(raw_source.lower(), raw_source)

    def fetch_cve_data(self, cve_id):
        cve_clean = cve_id.upper().strip()
        params = {"cveId": cve_clean}
        
        is_kev = cve_clean in self._get_cisa_kev_list()

        try:
            # Request NVD data
            res = requests.get(self.nvd_url, headers=self.headers, params=params, timeout=12)
            
            # Handle rate-limiting transparently with a brief retry
            if res.status_code == 403 or res.status_code == 503:
                time.sleep(2)
                res = requests.get(self.nvd_url, headers=self.headers, params=params, timeout=12)

            if res.status_code != 200:
                print(f"[!] NVD Fetch Failed: Received HTTP Status {res.status_code}")
                return None

            data = res.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                print(f"[!] Vulnerability {cve_clean} not found in NVD database.")
                return None
            
            cve_item = vulnerabilities[0].get("cve", {})
            metrics = cve_item.get("metrics", {})
            
            cvss_v3_assessments = []
            cvss_v2_assessments = []
            primary_v3_score = "N/A"

            # --- Extract CVSS v3.x ---
            for key in ["cvssMetricV31", "cvssMetricV30"]:
                if key in metrics:
                    for entry in metrics[key]:
                        cvss_data = entry.get("cvssData", {})
                        raw_src = entry.get("source", "NVD")
                        clean_src = self._format_source(raw_src)
                        
                        if "cisa" in clean_src.lower():
                            source_label = f"ADP: {clean_src}"
                        elif "nist" in clean_src.lower() or raw_src.lower() == "nvd@nist.gov":
                            source_label = "NIST: NVD"
                        else:
                            source_label = f"CNA / Source: {clean_src}"

                        score = cvss_data.get("baseScore", "Not Published")
                        if primary_v3_score == "N/A" and score != "Not Published":
                            primary_v3_score = str(score)

                        cvss_v3_assessments.append({
                            "score": score,
                            "severity": cvss_data.get("baseSeverity", entry.get("baseSeverity", "UNKNOWN")),
                            "source": source_label,
                            "vector": cvss_data.get("vectorString", "N/A")
                        })

            # --- Extract CVSS v2 ---
            if "cvssMetricV2" in metrics:
                for entry in metrics["cvssMetricV2"]:
                    cvss_data = entry.get("cvssData", {})
                    raw_src = entry.get("source", "NVD")
                    clean_src = self._format_source(raw_src)
                    
                    source_label = "NIST: NVD" if "nist" in clean_src.lower() or raw_src.lower() == "nvd@nist.gov" else f"CNA / Source: {clean_src}"

                    cvss_v2_assessments.append({
                        "score": cvss_data.get("baseScore", "Not Published"),
                        "severity": entry.get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN")),
                        "source": source_label,
                        "vector": cvss_data.get("vectorString", "N/A")
                    })

            # Descriptions
            descriptions = cve_item.get("descriptions", [])
            desc = "No description available."
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", desc)
                    break

            # Vendor & Product Parsing
            vendor, product = "N/A", "N/A"
            cpes = cve_item.get("configurations", [])
            candidates = []
            for config in cpes:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        cpe_str = match.get("criteria", "")
                        parts = cpe_str.split(":")
                        if len(parts) > 4:
                            candidates.append((parts[3], parts[4]))

            if candidates:
                desc_lower = desc.lower()
                best_pair = candidates[0]
                best_score = -1
                for v, p in candidates:
                    score = 0
                    v_clean = v.replace("_", " ").lower()
                    p_clean = p.replace("_", " ").lower()
                    if v_clean in desc_lower or v.lower() in desc_lower:
                        score += 3
                    if p_clean in desc_lower or p.lower() in desc_lower:
                        score += 4
                    if score > best_score:
                        best_score = score
                        best_pair = (v, p)
                vendor, product = best_pair

            primary_severity = "UNKNOWN"
            primary_vector = ""
            if cvss_v3_assessments:
                primary_severity = cvss_v3_assessments[0]["severity"]
                primary_vector = cvss_v3_assessments[0]["vector"]
            elif cvss_v2_assessments:
                primary_severity = cvss_v2_assessments[0]["severity"]
                primary_vector = cvss_v2_assessments[0]["vector"]

            cwe_id = "NVD-CWE-noinfo"
            weaknesses = cve_item.get("weaknesses", [])
            if weaknesses:
                cwe_desc = weaknesses[0].get("description", [])
                if cwe_desc:
                    cwe_id = cwe_desc[0].get("value", "NVD-CWE-noinfo")

            refs = [r.get("url") for r in cve_item.get("references", []) if r.get("url")]

            return {
                "cve_id": cve_clean,
                "description": desc,
                "vendor": vendor,
                "product": product,
                "primary_v3_score": primary_v3_score,
                "cvss_v3_assessments": cvss_v3_assessments,
                "cvss_v2_assessments": cvss_v2_assessments,
                "cvss_severity": primary_severity,
                "cvss_vector": primary_vector,
                "cwe": cwe_id,
                "published": cve_item.get("published", "")[:10],
                "modified": cve_item.get("lastModified", "")[:10],
                "is_kev": is_kev,
                "references": refs
            }

        except Exception as e:
            print(f"[!] CVE Collection Exception: {e}")
            return None
