# exporter.py
import os
import requests

WEBHOOK_URL = "https://mazenhassane.app.n8n.cloud/webhook-test/2ca99742-898a-4579-896b-410b961fac6b"

def get_code_context(filepath: str, line_start: int, line_end: int, margin: int = 2) -> str:
    """
    Opens the target file and extracts the vulnerable lines plus a margin 
    of surrounding lines (default +/- 2 lines) for LLM context.
    """
    try:
        with open(filepath, "r", errors="ignore") as f:
            lines = f.readlines()
            
        # Convert 1-based line numbers to 0-based list indices
        # Ensure we don't index below 0 or beyond the file length
        start_idx = max(0, line_start - 1 - margin)
        end_idx = min(len(lines), line_end + margin)
        
        # Extract the chunk and join it back into a string
        context_block = "".join(lines[start_idx:end_idx])
        return context_block
    except Exception as e:
        return f"// Error retrieving context: {e}"

def export_to_n8n(findings, timestamp):
    if not findings:
        print("  [*] No findings to export. Skipping n8n.")
        return

    print("[*] Gathering code context & firing webhook to n8n...")
    
    # 1. Loop through findings and inject the surrounding context block
    for finding in findings:
        filepath = finding.get("file")
        l_start = finding.get("line_start")
        l_end = finding.get("line_end")
        
        if filepath and l_start:
            finding["code_context"] = get_code_context(filepath, l_start, l_end, margin=2)
        else:
            finding["code_context"] = finding.get("code", "")

    # 2. Package it up with our unified timestamp
    unique_scan_name = f"Scan_{timestamp}"
    payload = {
        "sheet_name": unique_scan_name,
        "findings": findings
    } 

    # 3. Fire to n8n
    try:
        response = requests.post(WEBHOOK_URL, json=payload, timeout=10)
        
        if response.status_code == 200:
            print(f"  [✓] Payload successfully caught by n8n! (ID: {unique_scan_name})")
        else:
            print(f"  [!] n8n returned status {response.status_code}: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"  [!] Webhook request failed: {e}")
