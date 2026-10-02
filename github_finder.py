import requests

class GitHubFinder:
    def __init__(self):
        self.search_url = "https://api.github.com/search/repositories"

    def search_pocs(self, cve_id):
        cve_clean = cve_id.upper().strip()
        # Strictly search for repos with the specific CVE in name/description
        query = f'"{cve_clean}" in:name,description'
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Mozilla/5.0"
        }
        params = {
            "q": query,
            "sort": "stars",
            "order": "desc",
            "per_page": 10
        }

        pocs = []
        try:
            res = requests.get(self.search_url, headers=headers, params=params, timeout=10)
            if res.status_code == 200:
                items = res.json().get("items", [])
                for item in items:
                    repo_name = item.get("name", "")
                    full_name = item.get("full_name", "")
                    desc = item.get("description", "") or ""

                    # Filter out generic collection repositories or lists
                    if "poclist" in repo_name.lower() or "awesome-poc" in repo_name.lower():
                        continue

                    pocs.append({
                        "title": full_name,
                        "url": item.get("html_url"),
                        "stars": item.get("stargazers_count", 0),
                        "description": desc
                    })
        except Exception:
            pass
        return pocs
