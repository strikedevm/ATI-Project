import json
from config import MISTRAL_API_KEY, MISTRAL_MODEL
import llm

class AIGenerator:
    """
    Unified AI Threat Intelligence & Lab Generation Engine.
    Uses the multi-provider cascade in llm.py (Groq, Gemini, Mistral, OpenRouter, Cerebras, Ollama)
    with automatic provider failover, rate-limit cooldown, and telemetry.
    """
    def __init__(self):
        self.mistral_key = MISTRAL_API_KEY

    def generate_lab_environment(self, cve_data):
        """
        Generates a comprehensive replication sandbox using the multi-provider cascade.
        """
        result = llm.generate_lab_environment(cve_data)
        
        # If multi-provider cascade had an error and legacy Mistral key is present, try fallback
        if "error" in result and self.mistral_key:
            try:
                from mistralai.client import MistralClient
                from mistralai.models.chat_completion import ChatMessage
                client = MistralClient(api_key=self.mistral_key)
                prompt = f"""
                You are a Vulnerability Research AI. Generate a secure Docker/VM validation lab environment plan for {cve_data['cve_id']} affecting {cve_data['vendor']} {cve_data['product']}.
                Description: {cve_data['description']}

                Provide the output EXCLUSIVELY in the following JSON schema format without markdown blocks:
                {{
                    "docker_recommendation": "Docker code blueprint snippet or string",
                    "vm_recommendation": "VM OS and configuration suggestions",
                    "dependencies": ["list", "of", "packages"],
                    "ports": [80, 443],
                    "credentials": "Default or custom setup accounts",
                    "installation_steps": ["step 1", "step 2"],
                    "verification_steps": ["validation command 1", "validation command 2"],
                    "lab_difficulty": "Low/Medium/High"
                }}
                """
                messages = [ChatMessage(role="user", content=prompt)]
                chat_response = client.chat(model=MISTRAL_MODEL, messages=messages)
                raw_content = chat_response.choices[0].message.content.strip()
                if raw_content.startswith("```json"):
                    raw_content = raw_content[7:-3].strip()
                elif raw_content.startswith("```"):
                    raw_content = raw_content[3:-3].strip()
                data = json.loads(raw_content)
                data["generated_by"] = f"Mistral Direct ({MISTRAL_MODEL})"
                return data
            except Exception:
                pass

        return result

    def analyze_cve(self, cve_id, description_or_data):
        """
        Extracts structured intelligence (summary, action, poc, vendor, product, keywords, model).
        """
        return llm.analyze_individual_cve(cve_id, description_or_data)

    def classify_link(self, text_content, url=None):
        """
        Classifies link into POC, VENDOR_FIX, or INFO.
        """
        return llm.ai_link_classifier(text_content, url=url)

    def get_status(self):
        """
        Returns telemetry and status of all configured LLM providers.
        """
        return llm.get_llm_status()
