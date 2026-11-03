import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# Pointing the standard client to Groq's free endpoint
client = OpenAI(
    base_url="https://api.groq.com/openai/v1",
    api_key=os.getenv("GROQ_API_KEY")
)

def parse_prompt_with_ai(user_prompt):
    """Parses a natural language prompt into a structured targeting dictionary."""
    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",  # Updated to the current active free-tier model
            messages=[
                {
                    "role": "system", 
                    "content": (
                        "You are an AI assistant built for an advanced network scanner. "
                        "Parse the user's prompt to extract the target IP/domain, start_port, and end_port. "
                        "If ports are not mentioned, default to start_port: 1 and end_port: 1024. "
                        "Respond ONLY with a valid JSON object matching this schema: "
                        '{"target": "string", "start_port": int, "end_port": int}'
                    )
                },
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"}
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        return {"target": "127.0.0.1", "start_port": 21, "end_port": 80, "error": str(e)}

def generate_ai_report(scan_data):
    """Processes open ports and evaluates vulnerability mappings using open-source models."""
    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",  # Updated to the current active free-tier model
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert Security Analyst. Review the following raw port scanner JSON output. "
                        "Identify any software vulnerabilities or CVE mapping items corresponding to the versions found. "
                        "Output your response cleanly formatted as an HTML document fragment (use standard <h3>, <p>, <ul>, <li> tags, "
                        "no markdown block notations) detailing: Executive Summary, Vulnerability Assessment, and Remediation Steps."
                    )
                },
                {"role": "user", "content": json.dumps(scan_data)}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"<p>Error generating automated report: {str(e)}</p>"