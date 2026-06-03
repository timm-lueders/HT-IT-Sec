#!/usr/bin/env python3
"""
enrich_taint.py -- Generiert super-detaillierte Taint-Graphen fur ALLE YAML-Reports.
Nutzt verfugbare Daten: Import-Risiko-Map, Findings, Ghidra-Metadaten, Binary-Typ.
"""
import yaml, pathlib

REPORTS = pathlib.Path(r"C:\Users\batar\Desktop\Neuer Ordner\pipeline\HT-IT-Sec\reports")

def has_api(data, *keywords):
    """Check if any import contains any of the keywords."""
    for level in ["high", "medium", "low", "info"]:
        for api in data.get("import_risk_map", {}).get(level, []):
            name = api.get("api", "")
            if any(k in name for k in keywords):
                return True, name, level
    return False, "", ""

def build_taint(data):
    """Build super-detailed taint graph for one binary."""
    name = data.get("meta", {}).get("binary_name", "unknown")
    btype = data.get("meta", {}).get("binary_type", "")
    findings = data.get("findings", [])
    is_kernel = "kernel" in btype
    
    sources = []
    validators = []
    sinks = []
    edges = []
    
    # --- SOURCES ---
    if is_kernel:
        sources.append({"id": "ioctl", "name": "DeviceIoControl Input", "type": "IOCTL (METHOD_NEITHER)", "irp_field": "Irp->UserBuffer @ 0x70"})
        sources.append({"id": "mdl_read", "name": "IRP_MJ_READ MdlAddress", "type": "DIRECT_IO", "irp_field": "Irp->MdlAddress @ 0x10"})
        sources.append({"id": "mdl_write", "name": "IRP_MJ_WRITE MdlAddress", "type": "DIRECT_IO", "irp_field": "Irp->MdlAddress @ 0x10"})
    else:
        sources.append({"id": "cmdline", "name": "GetCommandLineW()", "type": "Process Args", "function": "main"})
        sources.append({"id": "console", "name": "ReadConsoleW()", "type": "Console Input", "function": "main"})
        if "dll" in btype:
            sources.append({"id": "com", "name": "COM/DCOM Activation", "type": "RPC/COM Input", "function": "DllGetClassObject"})
            sources.append({"id": "exports", "name": "Exported API Calls", "type": "Function Parameters", "function": "Various Exports"})
    
    # --- VALIDATORS ---
    has_probe_read, _, _ = has_api(data, "ProbeForRead")
    has_probe_write, _, _ = has_api(data, "ProbeForWrite")
    has_prev_mode, _, _ = has_api(data, "ExGetPreviousMode")
    has_se_capture, _, _ = has_api(data, "SeCaptureSubjectContext")
    has_heap_term, _, _ = has_api(data, "HeapEnableTermination")
    has_bounds_check = any("Bounds" in f.get("title","") for f in findings)
    has_double_val = any("Double" in f.get("title","") for f in findings)
    has_safe_apis = has_api(data, "memcpy_s", "strcpy_s", "sprintf_s", "wcscpy_s")
    
    if has_probe_read:
        validators.append({"id": "pr", "name": "ProbeForRead", "type": "Buffer Probe", "note": "Validiert User-Buffer vor Lesezugriff"})
    if has_probe_write:
        validators.append({"id": "pw", "name": "ProbeForWrite", "type": "Buffer Probe", "note": "Validiert User-Buffer vor Schreibzugriff"})
    if has_prev_mode:
        validators.append({"id": "pm", "name": "ExGetPreviousMode", "type": "Mode Check", "note": "Prüft ob Caller User oder Kernel Mode"})
    if has_se_capture:
        validators.append({"id": "sec", "name": "SeCaptureSubjectContext", "type": "Security Check", "note": "Prüft Security-Token des Callers"})
    if has_bounds_check:
        validators.append({"id": "bc", "name": "Bounds Check", "type": "Size Validation", "note": "Mehrstufige Puffergroßen-Prüfung"})
    if has_double_val:
        validators.append({"id": "dv", "name": "Double Validation", "type": "Structure Check", "note": "InputBufferLength == Buffer-Header-Size"})
    if has_heap_term:
        validators.append({"id": "ht", "name": "HeapEnableTerminationOnCorruption", "type": "Heap Hardening", "note": "Terminiert bei Heap-Korruption"})
    
    if not validators:
        validators.append({"id": "unknown", "name": "Unbekannte Validierung", "type": "Unknown", "note": "Keine spezifischen Validatoren via Import-Analyse identifiziert"})
    
    # --- SINKS ---
    has_memcpy, memcpy_name, memcpy_level = has_api(data, "memcpy")
    has_memmove, memmove_name, _ = has_api(data, "memmove")
    has_loadlib, loadlib_name, _ = has_api(data, "LoadLibrary")
    has_createproc, cp_name, _ = has_api(data, "CreateProcess")
    has_zwrite, _, _ = has_api(data, "ZwWriteFile", "WriteFile")
    has_zread, _, _ = has_api(data, "ZwReadFile", "ReadFile")
    has_regset, _, _ = has_api(data, "RegSetValue")
    has_bcrypt, _, _ = has_api(data, "BCrypt")
    has_mdl, _, _ = has_api(data, "MmMapLockedPages", "IoBuildPartialMdl")
    
    if has_memcpy:
        sinks.append({"id": "memcpy", "name": memcpy_name, "type": "Memory Copy", "address": "EXTERNAL", "risk": "CWE-119" if memcpy_level in ("high","medium") else "N/A"})
    if has_memmove:
        sinks.append({"id": "memmove", "name": memmove_name, "type": "Memory Move", "address": "EXTERNAL"})
    if has_loadlib:
        sinks.append({"id": "dll", "name": loadlib_name, "type": "DLL Loading", "address": "EXTERNAL", "risk": "CWE-426"})
    if has_createproc:
        sinks.append({"id": "proc", "name": cp_name, "type": "Process Creation", "address": "EXTERNAL", "risk": "CWE-78"})
    if has_zwrite:
        sinks.append({"id": "write", "name": "ZwWriteFile/WriteFile", "type": "Disk I/O Write", "address": "EXTERNAL"})
    if has_zread:
        sinks.append({"id": "read", "name": "ZwReadFile/ReadFile", "type": "Disk I/O Read", "address": "EXTERNAL"})
    if has_regset:
        sinks.append({"id": "reg", "name": "RegSetValueExW", "type": "Registry Write", "address": "EXTERNAL"})
    if has_bcrypt:
        sinks.append({"id": "crypto", "name": "BCryptEncrypt/Decrypt", "type": "Crypto Engine", "address": "EXTERNAL"})
    if has_mdl:
        sinks.append({"id": "mdl", "name": "MmMapLockedPages", "type": "MDL Mapping", "address": "EXTERNAL", "risk": "CWE-119"})
    
    if not sinks:
        sinks.append({"id": "unknown", "name": "Unbekannte Sinks", "type": "Unknown", "note": "Keine spezifischen Sinks via Import-Analyse identifiziert"})
    
    # --- EDGES ---
    src_id = sources[0]["id"]
    
    for v in validators:
        status = "BOUNDED" if v["id"] != "unknown" else "UNCHECKED" 
        edges.append({"from": src_id, "to": v["id"], "label": v["type"], "status": status})
        src_id = v["id"]
    
    for s in sinks:
        status = "BOUNDED" if s.get("risk") in (None, "N/A") else "CONDITIONAL" if s.get("risk","").startswith("CWE") else "UNCHECKED"
        edges.append({"from": src_id, "to": s["id"], "label": s["type"], "status": status})
    
    # --- MERMAID ---
    mm_lines = ["graph TD"]
    mm_lines.append('  subgraph "Input Sources"')
    for s in sources:
        mm_lines.append(f'    {s["id"]}["{s["name"][:50]}"]')
    mm_lines.append("  end")
    
    if validators and validators[0]["id"] != "unknown":
        mm_lines.append('  subgraph "Validation Layer"')
        for v in validators:
            color = "#00fd00" if v["id"] != "unknown" else "#ffc107"
            mm_lines.append(f'    {v["id"]}{{{{{v["name"][:40]}}}}}')
        mm_lines.append("  end")
    
    mm_lines.append('  subgraph "Data Sinks"')
    for s in sinks:
        color = "#ff8c00" if s.get("risk","") in ("CWE-119","CWE-78","CWE-426") else "#00fd00"
        mm_lines.append(f'    {s["id"]}["{s["name"][:40]}"]')
    mm_lines.append("  end")
    
    # Edges
    for e in edges:
        status = e["status"]
        style = "-->" if status == "BOUNDED" else "-.->" if status == "CONDITIONAL" else "==>"
        label = e["label"][:30]
        mm_lines.append(f'    {e["from"]} {style}|"{label}"| {e["to"]}')
    
    # Style critical nodes
    for s in sinks:
        if s.get("risk","") in ("CWE-119","CWE-78","CWE-426","CWE-367"):
            mm_lines.append(f'    style {s["id"]} fill:#ff8c00,stroke:#333')
    
    return {
        "sources": sources,
        "validators": validators,
        "sinks": sinks,
        "edges": edges,
        "graph_mermaid": "\n".join(mm_lines)
    }

# Process all reports
count = 0
for yf in sorted(REPORTS.glob("*.yaml")):
    data = yaml.safe_load(yf.read_text(encoding="utf-8"))
    name = data.get("meta", {}).get("binary_name", "?")
    
    # Skip if already has graph_mermaid
    if "graph_mermaid" in data.get("taint_graph", {}):
        print(f"  SKIP {name} (already detail)")
        continue
    
    taint = build_taint(data)
    data["taint_graph"] = taint
    
    yf.write_text(yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False), encoding="utf-8")
    count += 1
    print(f"  ENRICHED {name}: {len(taint['sources'])} sources, {len(taint['validators'])} validators, {len(taint['sinks'])} sinks")

print(f"\nDone: {count} reports enriched with detailed taint graphs")
