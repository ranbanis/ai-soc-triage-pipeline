# AI-Powered SOC Alert Triage Pipeline

An automated incident response pipeline that ingests raw SIEM alerts, enriches Indicators of Compromise (IOCs) using threat intelligence APIs, and leverages LLMs (via LangChain and OpenAI) to generate actionable, natural-language triage summaries for L1/L2 SOC analysts.

## Features
* **Automated Ingestion:** Parses JSON-formatted alerts from SIEMs (Splunk, Sentinel, etc.).
* **IOC Enrichment:** Automatically queries VirusTotal and GreyNoise for IP/Hash reputation.
* **Alert Clustering:** Groups related alerts based on common IOCs or attack vectors.
* **AI Summarization:** Uses LangChain to prompt OpenAI models to analyze the enriched data and output a structured triage report with recommended next steps.

## Prerequisites
* Python 3.8+
* OpenAI API Key
* VirusTotal API Key
* GreyNoise API Key

## Setup and Usage
1. Clone the repository: `git clone https://github.com/yourusername/ai-soc-triage-pipeline.git`
2. Install dependencies: `pip install -r requirements.txt`
3. Rename `.env.example` to `.env` and add your API keys.
4. Run the pipeline: `python triage_pipeline.py`

## Example Output
The script generates a summary like this:
> **Triage Summary [CRITICAL]**: Multiple login failures followed by a successful login from IP `198.51.100.23`. GreyNoise flags this IP as a known brute-force scanner. VirusTotal shows 12 security vendors flagged the associated payload hash. 
> **Recommendation**: Immediately isolate the host, force password reset, and investigate post-compromise activity.
