import json

def format_json_output(cve_data, github_pocs, exploits, ai_intel, lab_builder):
    # Aggregates system metrics into an exportable standard schema
    return json.dumps({
        "metadata": cve_data,
        "intel": ai_intel,
        "pocs": {
            "github": github_pocs,
            "exploits": exploits
        },
        "lab_blueprint": lab_builder
    }, indent=4)
