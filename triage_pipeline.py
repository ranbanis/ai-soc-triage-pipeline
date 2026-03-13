import os
import json
import requests
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain

# Load environment variables
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")

class ThreatEnricher:
    """Handles external API calls for IOC enrichment."""
    
    @staticmethod
    def check_virustotal(ioc):
        # Simplified VT integration for proof-of-concept
        if not VT_API_KEY:
            return "VirusTotal API key missing. Mock data: 5/72 vendors flagged as malicious."
        
        url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
        headers = {"x-apikey": VT_API_KEY}
        try:
            response = requests.get(url, headers=headers)
            return response.json()
        except Exception as e:
            return f"VT Error: {str(e)}"

    @staticmethod
    def check_greynoise(ip_address):
        # Simplified GreyNoise integration
        if not GREYNOISE_API_KEY:
            return "GreyNoise API key missing. Mock data: IP known for SSH brute-forcing."
        
        url = f"https://api.greynoise.io/v3/community/{ip_address}"
        headers = {"key": GREYNOISE_API_KEY}
        try:
            response = requests.get(url, headers=headers)
            return response.json()
        except Exception as e:
            return f"GreyNoise Error: {str(e)}"

class AlertTriageAgent:
    """Uses LangChain and OpenAI to summarize the enriched alert."""
    
    def __init__(self):
        # Initialize the LLM (gpt-3.5-turbo or gpt-4)
        self.llm = ChatOpenAI(temperature=0.2, openai_api_key=OPENAI_API_KEY)
        
        # Define the prompt template for the L1 Analyst output
        self.template = """
        You are a senior SOC analyst. Review the following SIEM alert and the associated threat intelligence enrichment data.
        
        SIEM Alert Details:
        {alert_data}
        
        Threat Intel Enrichment:
        {enrichment_data}
        
        Please provide a concise, natural-language triage summary for an L1 analyst. 
        Include:
        1. A brief executive summary of the threat.
        2. The severity level (Low, Medium, High, Critical).
        3. 2-3 specific, actionable next steps for remediation or further investigation.
        """
        self.prompt = PromptTemplate(input_variables=["alert_data", "enrichment_data"], template=self.template)
        self.chain = LLMChain(llm=self.llm, prompt=self.prompt)

    def generate_summary(self, alert, enrichment):
        return self.chain.run(alert_data=json.dumps(alert), enrichment_data=json.dumps(enrichment))

def main():
    # Load sample alerts (Mocking a SIEM ingestion queue)
    try:
        with open('sample_alerts.json', 'r') as file:
            alerts = json.load(file)
    except FileNotFoundError:
        print("Error: sample_alerts.json not found. Please create one.")
        return

    enricher = ThreatEnricher()
    agent = AlertTriageAgent()

    for alert in alerts:
        print(f"\n--- Triaging Alert: {alert.get('alert_name', 'Unknown')} ---")
        
        # Extract IOCs (Assuming JSON contains 'source_ip' and 'file_hash')
        ip_ioc = alert.get("source_ip", "")
        hash_ioc = alert.get("file_hash", "")
        
        enrichment_results = {}
        
        if ip_ioc:
            print(f"[*] Enriching IP: {ip_ioc} via GreyNoise...")
            enrichment_results['GreyNoise'] = enricher.check_greynoise(ip_ioc)
            
        if hash_ioc:
            print(f"[*] Enriching Hash: {hash_ioc} via VirusTotal...")
            enrichment_results['VirusTotal'] = enricher.check_virustotal(hash_ioc)

        print("[*] Generating AI Triage Summary...")
        triage_report = agent.generate_summary(alert, enrichment_results)
        
        print("\n=== L1 TRIAGE REPORT ===")
        print(triage_report)
        print("========================\n")

if __name__ == "__main__":
    main()
