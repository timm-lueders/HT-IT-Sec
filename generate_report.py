#!/usr/bin/env python3
"""
generate_report.py -- Befullt das YAML-Template mit GhidraMCP-API-Daten.
Aufruf: python generate_report.py <binary_name> <ghidra_mcp_url>

Der LLM ruft vorher alle GhidraMCP-Endpunkte ab und ubergibt die
Daten als JSON-Dateien oder direkt per Kommandozeile.

Simpler Modus (ohne Ghidra): python generate_report.py --template-only
Erzeugt ein leeres Template zum manuellen Befullen.
"""
import sys, json, os, hashlib
from datetime import datetime
from pathlib import Path

TEMPLATE_PATH = Path(__file__).parent / "template.yaml"
REPORTS_DIR = Path(__file__).parent / "reports"

def load_template():
    """Liest das Template und gibt ein Dict zuruck."""
    import yaml
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)

def create_empty_report(binary_name, binary_type="user_exe"):
    """Erzeugt ein leeres Report-Template."""
    t = load_template()
    t["meta"]["binary_name"] = binary_name
    t["meta"]["binary_type"] = binary_type
    t["meta"]["analysis_date"] = datetime.now().strftime("%Y-%m-%d")
    return t

def fill_from_ghidra_batch(report, ghidra_data_dir):
    """
    Befullt Report aus einem Verzeichnis mit GhidraMCP JSON-Responses.
    Erwartete Dateien:
      metadata.json     -> get_metadata
      entry_points.json -> get_entry_points
      imports.json      -> list_imports
      function_count.json -> get_function_count
      findings.json     -> manuell erstellte Findings
    """
    def load_json(name):
        p = Path(ghidra_data_dir) / name
        return json.loads(p.read_text()) if p.exists() else {}

    meta = load_json("metadata.json")
    if meta:
        report["binary_info"]["architecture"] = meta.get("Architecture", "")
        report["binary_info"]["base_address"] = meta.get("Base Address", "")
        report["binary_info"]["function_count"] = meta.get("Function Count", 0)
        report["binary_info"]["symbol_count"] = meta.get("Symbol Count", 0)
        report["binary_info"]["compiler_hint"] = meta.get("Compiler", "")
        report["binary_info"]["subsystem"] = meta.get("Language", "")
        report["meta"]["file_size_bytes"] = meta.get("Total Memory Size", 0)

    ep = load_json("entry_points.json")
    if ep:
        report["binary_info"]["entry_point"] = str(ep)

    fc = load_json("function_count.json")
    if fc and isinstance(fc, dict):
        report["binary_info"]["function_count"] = fc.get("function_count", 0)
    
    findings = load_json("findings.json")
    if findings and isinstance(findings, list):
        report["findings"] = findings

    return report

def fill_pe_security(report, pe_data: dict):
    """Befullt PE-Security-Flags aus einem Dict."""
    p = report["pe_security"]
    p["aslr"] = pe_data.get("aslr", False)
    p["dep"] = pe_data.get("dep", False)
    p["cfg"] = pe_data.get("cfg", False)
    p["high_entropy_aslr"] = pe_data.get("high_entropy_aslr", False)
    return report

def fill_import_risk(report, risk_map: dict):
    """Befullt die Import-Risiko-Matrix."""
    for level in ["high", "medium", "low", "info"]:
        if level in risk_map:
            report["import_risk_map"][level] = risk_map[level]
    return report

def fill_findings(report, findings: list):
    """Fugt Findings hinzu."""
    existing = report.get("findings", [])
    for f in findings:
        if not any(e.get("id") == f.get("id") for e in existing):
            existing.append(f)
    report["findings"] = existing
    return report

def fill_tools(report, tool_name: str, data: dict):
    """Befullt die Tools-Output-Sektion."""
    if tool_name in report["tools_output"]:
        report["tools_output"][tool_name].update(data)
    return report

def save_report(report, filename=None):
    """Speichert Report als YAML."""
    import yaml
    REPORTS_DIR.mkdir(exist_ok=True)
    name = filename or report["meta"]["binary_name"].replace(".", "_")
    out = REPORTS_DIR / f"{name}.yaml"
    with open(out, "w", encoding="utf-8") as f:
        yaml.dump(report, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    print(f"Report gespeichert: {out}")
    return out

def compute_md5(filepath):
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest().upper()

# ================================================================
# HAUPTFUNKTION -- so rufen LLMs das Skript auf
# ================================================================
if __name__ == "__main__":
    if "--template-only" in sys.argv:
        name = sys.argv[-1] if len(sys.argv) > 2 else "unknown_binary"
        report = create_empty_report(name)
        save_report(report)
        print("Leeres Template erstellt. Jetzt manuell befullen.")
        sys.exit(0)
    
    if len(sys.argv) < 2:
        print("Usage: python generate_report.py <binary_name> [ghidra_data_dir]")
        print("       python generate_report.py --template-only [name]")
        sys.exit(1)
    
    binary_name = sys.argv[1]
    report = create_empty_report(binary_name)
    
    # Aus Datei-Hash berechnen falls Binary im gleichen Verzeichnis
    if os.path.exists(binary_name):
        report["meta"]["md5"] = compute_md5(binary_name)
        report["meta"]["file_size_bytes"] = os.path.getsize(binary_name)
    
    # Aus GhidraMCP-Daten befullen
    if len(sys.argv) > 2:
        fill_from_ghidra_batch(report, sys.argv[2])
    
    save_report(report)
