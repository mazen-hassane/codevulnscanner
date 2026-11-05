# main.py

import os
import sys
import pyfiglet
from colorama import init, Fore, Style
from collections import Counter

import config
import scanner
import parser
import reporter
import llm_analyzer
import exporter

init(autoreset=True)


def print_banner():
    print(Fore.WHITE + "\n  Welcome to")
    title = pyfiglet.figlet_format("CodeVulnScan", font="slant")
    print(Fore.CYAN + Style.BRIGHT + title)
    print(Fore.WHITE + "  Powered by AI")
    print(Fore.WHITE + "  Made by m.hassane")
    print(Fore.WHITE + "\n" + "-" * 55 + "\n")


def get_target_path() -> str:
    while True:
        print(Fore.YELLOW + "  Enter target directory path:")
        print(Fore.WHITE  + f"  (Press Enter to use default: {config.TARGET_PATH})")
        user_input = input(Fore.GREEN + "  >> " + Style.RESET_ALL).strip()

        path = user_input if user_input else config.TARGET_PATH

        if os.path.exists(path):
            if os.path.isdir(path):
                print(Fore.GREEN + f"\n  [✓] Target set to: {path}\n")
                return path
            else:
                print(Fore.RED + "\n  [!] That path is a file not a directory. Please try again.\n")
        else:
            print(Fore.RED + f"\n  [!] Path does not exist: {path}. Please try again.\n")


def print_language_summary(findings: list):
    print(f"\n[*] Unique findings after deduplication:")
    lang_counts = Counter(
        f["file"].split(os.sep)[-1].split(".")[-1]
        for f in findings
    )
    for ext, count in sorted(lang_counts.items()):
        print(f"    .{ext:<8} → {count} findings")

# ... (keep your imports and helper functions exactly the same) ...
def run_scan(target_path: str):
    print(Fore.GREEN + f"\n  [✓] Target set to: {target_path}\n")
    
    raw_findings = scanner.scan(target_path)

    if not raw_findings:
        print(Fore.YELLOW + "\n[*] No findings. Exiting.")
        return

    # ─── Generate ONE unified timestamp for this entire run ───
    scan_timestamp = reporter.generate_timestamp()

    # Pass the same timestamp everywhere
    reporter.save_llm_queue(raw_findings, scan_timestamp)
    
    clean_findings = parser.parse(raw_findings)
    print_language_summary(clean_findings)
    
    # Now this function takes our unified timestamp
    reporter.save_report_and_print(clean_findings, scan_timestamp)
    
    # ─── Fire the data to n8n with the same timestamp ───
    exporter.export_to_n8n(clean_findings, scan_timestamp)
    # ────────────────────────────────────────────────────
    
    #llm_analyzer.run()

def main():
    # This keeps your CLI working if you ever want to run it without the GUI
    print_banner()
    target_path = get_target_path()
    run_scan(target_path)

if __name__ == "__main__":
    main()
