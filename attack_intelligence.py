class AttackIntelligence:
    def parse_vector(self, vector_str):
        # Extracts detailed matrices straight from standard CVSS strings
        intel = {
            "Attack Vector": "Unknown",
            "Attack Complexity": "Unknown",
            "Privileges Required": "Unknown",
            "User Interaction": "Unknown",
            "Authentication Required": "No"
        }
        if not vector_str:
            return intel

        parts = vector_str.split("/")
        for part in parts:
            if part.startswith("AV:"):
                mapping = {"N": "Network", "A": "Adjacent Network", "L": "Local", "P": "Physical"}
                intel["Attack Vector"] = mapping.get(part[3:], "Unknown")
            elif part.startswith("AC:"):
                mapping = {"L": "Low", "H": "High"}
                intel["Attack Complexity"] = mapping.get(part[3:], "Unknown")
            elif part.startswith("PR:"):
                mapping = {"N": "None", "L": "Low", "H": "High"}
                intel["Privileges Required"] = mapping.get(part[3:], "Unknown")
                intel["Authentication Required"] = "Yes" if part[3:] != "N" else "No"
            elif part.startswith("UI:"):
                mapping = {"N": "None", "R": "Required"}
                intel["User Interaction"] = mapping.get(part[3:], "Unknown")
                
        return intel
