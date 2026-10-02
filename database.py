import os
import json
import sqlite3
import contextlib
from typing import Dict, List, Optional, Any

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, "vulnerability_intel.db")

class Database:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    @contextlib.contextmanager
    def _get_connection(self):
        """Context manager for SQLite connections that ensures auto-commit and closure."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        """Initializes tables and indexes for the platform."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Main CVE metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cves (
                    cve_id TEXT PRIMARY KEY,
                    vendor TEXT,
                    product TEXT,
                    description TEXT,
                    cvss_severity TEXT,
                    cwe TEXT,
                    primary_v3_score TEXT,
                    is_kev INTEGER DEFAULT 0,
                    published TEXT,
                    modified TEXT,
                    cvss_v3_assessments TEXT, -- JSON
                    cvss_v2_assessments TEXT, -- JSON
                    references_list TEXT,     -- JSON
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # 2. GitHub PoC Repositories
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS github_pocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    title TEXT,
                    url TEXT,
                    stars INTEGER DEFAULT 0,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cve_id) REFERENCES cves (cve_id) ON DELETE CASCADE
                );
            """)

            # 3. Exploit Intelligence (Vulhub, Exploit-DB, Metasploit, Nuclei, Writeups)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS exploit_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    source TEXT,
                    title TEXT,
                    url TEXT,
                    badge TEXT,
                    is_vulhub INTEGER DEFAULT 0,
                    docker_compose_url TEXT,
                    extra_data TEXT, -- JSON
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cve_id) REFERENCES cves (cve_id) ON DELETE CASCADE
                );
            """)

            # 4. AI Threat Intelligence & CISO Briefings
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ai_analysis (
                    cve_id TEXT PRIMARY KEY,
                    summary TEXT,
                    action TEXT,
                    poc TEXT,
                    vendor TEXT,
                    product TEXT,
                    keywords TEXT,
                    model_used TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cve_id) REFERENCES cves (cve_id) ON DELETE CASCADE
                );
            """)

            # 5. AI Lab Environment Blueprints
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS lab_blueprints (
                    cve_id TEXT PRIMARY KEY,
                    difficulty TEXT,
                    docker_recommendation TEXT,
                    vm_recommendation TEXT,
                    ports TEXT,               -- JSON
                    credentials TEXT,
                    installation_steps TEXT,  -- JSON
                    verification_steps TEXT,  -- JSON
                    generated_by TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cve_id) REFERENCES cves (cve_id) ON DELETE CASCADE
                );
            """)

            # 6. Search History & Activity Log
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS search_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    searched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Indexes for fast lookup
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_github_pocs_cve ON github_pocs(cve_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_exploit_intel_cve ON exploit_intelligence(cve_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_search_history_cve ON search_history(cve_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_search_history_time ON search_history(searched_at DESC);")

    # --------------------------------------------------------------------------
    # CVE & Threat Intelligence Storage & Retrieval
    # --------------------------------------------------------------------------
    def save_cve_data(self, cve_data: Dict[str, Any], github_pocs: List[Dict[str, Any]] = None, extra_intel: List[Dict[str, Any]] = None):
        """Saves or updates CVE metadata, PoCs, and exploit intelligence in a single transaction."""
        cve_id = cve_data.get("cve_id", "").upper().strip()
        if not cve_id:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Insert or replace CVE metadata
            cursor.execute("""
                INSERT INTO cves (
                    cve_id, vendor, product, description, cvss_severity, cwe,
                    primary_v3_score, is_kev, published, modified,
                    cvss_v3_assessments, cvss_v2_assessments, references_list, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(cve_id) DO UPDATE SET
                    vendor = excluded.vendor,
                    product = excluded.product,
                    description = excluded.description,
                    cvss_severity = excluded.cvss_severity,
                    cwe = excluded.cwe,
                    primary_v3_score = excluded.primary_v3_score,
                    is_kev = excluded.is_kev,
                    published = excluded.published,
                    modified = excluded.modified,
                    cvss_v3_assessments = excluded.cvss_v3_assessments,
                    cvss_v2_assessments = excluded.cvss_v2_assessments,
                    references_list = excluded.references_list,
                    updated_at = CURRENT_TIMESTAMP;
            """, (
                cve_id,
                cve_data.get("vendor", ""),
                cve_data.get("product", ""),
                cve_data.get("description", ""),
                cve_data.get("cvss_severity", ""),
                cve_data.get("cwe", ""),
                str(cve_data.get("primary_v3_score", "N/A")),
                1 if cve_data.get("is_kev") else 0,
                cve_data.get("published", ""),
                cve_data.get("modified", ""),
                json.dumps(cve_data.get("cvss_v3_assessments", [])),
                json.dumps(cve_data.get("cvss_v2_assessments", [])),
                json.dumps(cve_data.get("references", []))
            ))

            # Update GitHub PoCs if provided
            if github_pocs is not None:
                cursor.execute("DELETE FROM github_pocs WHERE cve_id = ?;", (cve_id,))
                for poc in github_pocs:
                    cursor.execute("""
                        INSERT INTO github_pocs (cve_id, title, url, stars, description)
                        VALUES (?, ?, ?, ?, ?);
                    """, (
                        cve_id,
                        poc.get("title", ""),
                        poc.get("url", ""),
                        int(poc.get("stars", 0)),
                        poc.get("description", "")
                    ))

            # Update Exploit Intelligence if provided
            if extra_intel is not None:
                cursor.execute("DELETE FROM exploit_intelligence WHERE cve_id = ?;", (cve_id,))
                for it in extra_intel:
                    cursor.execute("""
                        INSERT INTO exploit_intelligence (
                            cve_id, source, title, url, badge, is_vulhub, docker_compose_url, extra_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """, (
                        cve_id,
                        it.get("source", ""),
                        it.get("title", ""),
                        it.get("url", ""),
                        it.get("badge", "INTEL"),
                        1 if it.get("is_vulhub") else 0,
                        it.get("docker_compose_url", ""),
                        json.dumps({k: v for k, v in it.items() if k not in ("source", "title", "url", "badge", "is_vulhub", "docker_compose_url")})
                    ))

            # Record search history
            cursor.execute("INSERT INTO search_history (cve_id) VALUES (?);", (cve_id,))

    def get_cve_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves cached CVE intelligence dossier from SQLite."""
        cve_clean = cve_id.upper().strip()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cves WHERE cve_id = ?;", (cve_clean,))
            row = cursor.fetchone()
            if not row:
                return None

            cve_data = {
                "cve_id": row["cve_id"],
                "vendor": row["vendor"],
                "product": row["product"],
                "description": row["description"],
                "cvss_severity": row["cvss_severity"],
                "cwe": row["cwe"],
                "primary_v3_score": row["primary_v3_score"],
                "is_kev": bool(row["is_kev"]),
                "published": row["published"],
                "modified": row["modified"],
                "cvss_v3_assessments": json.loads(row["cvss_v3_assessments"] or "[]"),
                "cvss_v2_assessments": json.loads(row["cvss_v2_assessments"] or "[]"),
                "references": json.loads(row["references_list"] or "[]"),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"])
            }

            # Retrieve PoCs
            cursor.execute("SELECT title, url, stars, description FROM github_pocs WHERE cve_id = ? ORDER BY stars DESC;", (cve_clean,))
            github_pocs = [dict(r) for r in cursor.fetchall()]

            # Retrieve Exploit Intelligence
            cursor.execute("SELECT source, title, url, badge, is_vulhub, docker_compose_url, extra_data FROM exploit_intelligence WHERE cve_id = ?;", (cve_clean,))
            extra_intel = []
            for r in cursor.fetchall():
                item = {
                    "source": r["source"],
                    "title": r["title"],
                    "url": r["url"],
                    "badge": r["badge"],
                    "is_vulhub": bool(r["is_vulhub"]),
                    "docker_compose_url": r["docker_compose_url"]
                }
                extra = json.loads(r["extra_data"] or "{}")
                item.update(extra)
                extra_intel.append(item)

            return {
                "cve_data": cve_data,
                "github_pocs": github_pocs,
                "extra_intel": extra_intel
            }

    # --------------------------------------------------------------------------
    # AI Threat Analysis Storage & Retrieval
    # --------------------------------------------------------------------------
    def save_ai_analysis(self, cve_id: str, ai_data: Dict[str, Any]):
        """Caches AI threat analysis briefing."""
        cve_clean = cve_id.upper().strip()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ai_analysis (
                    cve_id, summary, action, poc, vendor, product, keywords, model_used, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(cve_id) DO UPDATE SET
                    summary = excluded.summary,
                    action = excluded.action,
                    poc = excluded.poc,
                    vendor = excluded.vendor,
                    product = excluded.product,
                    keywords = excluded.keywords,
                    model_used = excluded.model_used,
                    created_at = CURRENT_TIMESTAMP;
            """, (
                cve_clean,
                ai_data.get("summary", ""),
                ai_data.get("action", ""),
                ai_data.get("poc", ""),
                ai_data.get("vendor", ""),
                ai_data.get("product", ""),
                ai_data.get("keywords", ""),
                ai_data.get("model_used", "")
            ))

    def get_ai_analysis(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves cached AI threat analysis."""
        cve_clean = cve_id.upper().strip()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ai_analysis WHERE cve_id = ?;", (cve_clean,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "summary": row["summary"],
                "action": row["action"],
                "poc": row["poc"],
                "vendor": row["vendor"],
                "product": row["product"],
                "keywords": row["keywords"],
                "model_used": row["model_used"],
                "created_at": str(row["created_at"])
            }

    # --------------------------------------------------------------------------
    # AI Lab Blueprint Storage & Retrieval
    # --------------------------------------------------------------------------
    def save_lab_blueprint(self, cve_id: str, lab_data: Dict[str, Any]):
        """Caches AI synthesized replication lab blueprint."""
        cve_clean = cve_id.upper().strip()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO lab_blueprints (
                    cve_id, difficulty, docker_recommendation, vm_recommendation,
                    ports, credentials, installation_steps, verification_steps,
                    generated_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(cve_id) DO UPDATE SET
                    difficulty = excluded.difficulty,
                    docker_recommendation = excluded.docker_recommendation,
                    vm_recommendation = excluded.vm_recommendation,
                    ports = excluded.ports,
                    credentials = excluded.credentials,
                    installation_steps = excluded.installation_steps,
                    verification_steps = excluded.verification_steps,
                    generated_by = excluded.generated_by,
                    created_at = CURRENT_TIMESTAMP;
            """, (
                cve_clean,
                lab_data.get("lab_difficulty", "Medium"),
                lab_data.get("docker_recommendation", ""),
                lab_data.get("vm_recommendation", ""),
                json.dumps(lab_data.get("ports", [])),
                str(lab_data.get("credentials", "")),
                json.dumps(lab_data.get("installation_steps", [])),
                json.dumps(lab_data.get("verification_steps", [])),
                lab_data.get("generated_by", "AI Cascade")
            ))

    def get_lab_blueprint(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves cached lab replication blueprint."""
        cve_clean = cve_id.upper().strip()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM lab_blueprints WHERE cve_id = ?;", (cve_clean,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "lab_difficulty": row["difficulty"],
                "docker_recommendation": row["docker_recommendation"],
                "vm_recommendation": row["vm_recommendation"],
                "ports": json.loads(row["ports"] or "[]"),
                "credentials": row["credentials"],
                "installation_steps": json.loads(row["installation_steps"] or "[]"),
                "verification_steps": json.loads(row["verification_steps"] or "[]"),
                "generated_by": row["generated_by"],
                "created_at": str(row["created_at"])
            }

    # --------------------------------------------------------------------------
    # History & Platform Metrics
    # --------------------------------------------------------------------------
    def get_recent_searches(self, limit: int = 8) -> List[str]:
        """Returns distinct recent searches ordered by most recent."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT cve_id, MAX(searched_at) as last_seen
                FROM search_history
                GROUP BY cve_id
                ORDER BY last_seen DESC
                LIMIT ?;
            """, (limit,))
            return [row["cve_id"] for row in cursor.fetchall()]

    def get_platform_stats(self) -> Dict[str, int]:
        """Returns total records stored in SQLite database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM cves;")
            total_cves = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM github_pocs;")
            total_pocs = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM exploit_intelligence;")
            total_exploits = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM lab_blueprints;")
            total_labs = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM ai_analysis;")
            total_ai = cursor.fetchone()[0]

            return {
                "total_cves": total_cves,
                "total_pocs": total_pocs,
                "total_exploits": total_exploits,
                "total_labs": total_labs,
                "total_ai_analyses": total_ai
            }

    def get_all_cves(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns a list of all stored CVEs with summary metadata."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT cve_id, vendor, product, cvss_severity, primary_v3_score, is_kev, updated_at
                FROM cves
                ORDER BY updated_at DESC
                LIMIT ?;
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def delete_cve(self, cve_id: str) -> bool:
        """Deletes a CVE and cascades to PoCs, lab blueprints, and AI analyses."""
        cve_clean = cve_id.upper().strip()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cves WHERE cve_id = ?;", (cve_clean,))
            cursor.execute("DELETE FROM search_history WHERE cve_id = ?;", (cve_clean,))
            return cursor.rowcount > 0

    def clear_database(self):
        """Clears all records from the database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM github_pocs;")
            cursor.execute("DELETE FROM exploit_intelligence;")
            cursor.execute("DELETE FROM ai_analysis;")
            cursor.execute("DELETE FROM lab_blueprints;")
            cursor.execute("DELETE FROM search_history;")
            cursor.execute("DELETE FROM cves;")

# Singleton instance
db = Database()
