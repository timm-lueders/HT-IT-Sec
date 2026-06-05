#!/usr/bin/env python3
"""enrich_taint.py v2 - Smart taint graphs from ALL available data."""
import yaml, pathlib, re

REPORTS = pathlib.Path(r"C:\Users\batar\Desktop\Neuer Ordner\pipeline\HT-IT-Sec\reports")

def clean(s): return s.replace("("," ").replace(")"," ").replace("<br/>"," ").replace("<br>"," ")[:50]

def has_api(data, *kw):
    for lvl in ["high","medium","low","info"]:
        for a in data.get("import_risk_map",{}).get(lvl,[]):
            if any(k in a.get("api","") for k in kw): return True, a.get("api",""), lvl
    return False, "", ""

def has_in_findings(data, *kw):
    for f in data.get("findings",[]):
        txt = (f.get("title","")+" "+f.get("description","")).lower()
        if any(k.lower() in txt for k in kw): return True
    return False

def has_in_tools(data, *kw):
    cw = data.get("tools_output",{}).get("cwe_checker",{})
    if isinstance(cw, dict):
        for k in kw:
            if cw.get(k,0) > 0: return True
    return False

def build(data):
    nm = data.get("meta",{}).get("binary_name","?")
    k = "kernel" in data.get("meta",{}).get("binary_type","")
    
    srcs = []
    vals = []
    snks = []
    
    # --- SOURCES ---
    if k:
        srcs.append({"id":"ioctl","name":"DeviceIoControl Input","type":"IOCTL","detail":"Irp->UserBuffer @0x70"})
        srcs.append({"id":"mdl","name":"IRP_MJ_READ/WRITE Mdl","type":"DIRECT_IO","detail":"Irp->MdlAddress @0x10"})
        srcs.append({"id":"sysbuf","name":"IRP SystemBuffer","type":"METHOD_BUFFERED","detail":"Irp->AssociatedIrp.SystemBuffer"})
    else:
        srcs.append({"id":"cmdline","name":"GetCommandLineW","type":"Command Line Args","detail":"Process Startup"})
        srcs.append({"id":"console","name":"ReadConsoleW","type":"Console Input","detail":"Interactive Mode"})
        if has_api(data,"LoadLibrary")[0] or has_api(data,"CoCreate")[0]:
            srcs.append({"id":"com","name":"COM/DCOM/RPC Input","type":"RPC Call","detail":"Remote Activation"})
    
    # --- VALIDATORS ---
    hpw,_,_ = has_api(data,"ProbeForWrite"); hpr,_,_ = has_api(data,"ProbeForRead")
    hpm,_,_ = has_api(data,"ExGetPreviousMode")
    hsc,_,_ = has_api(data,"SeCapture")
    hsafe,_,_ = has_api(data,"memcpy_s","strcpy_s","sprintf_s")
    hstrsafe,_,_ = has_api(data,"_snwprintf_s","_vsnwprintf_s","swprintf_s")
    
    if hpw: vals.append({"id":"pw","name":"ProbeForWrite","type":"Buffer Probe","status":"BOUNDED"})
    if hpr: vals.append({"id":"pr","name":"ProbeForRead","type":"Buffer Probe","status":"BOUNDED"})
    if hpm: vals.append({"id":"pm","name":"ExGetPreviousMode","type":"User/Kernel Check","status":"BOUNDED"})
    if hsc: vals.append({"id":"sc","name":"SeCaptureSubjectContext","type":"Security Token Check","status":"BOUNDED"})
    
    # Safe API check
    if has_api(data,"memcpy")[0] and hsafe:
        vals.append({"id":"mix","name":"memcpy+memcpy_s gemischt","type":"⚠️ Inkonsistente API-Nutzung","status":"CONDITIONAL"})
    elif hsafe:
        vals.append({"id":"sapi","name":"Safe APIs (memcpy_s etc.)","type":"String/Mem Safety","status":"BOUNDED"})
    
    if has_in_findings(data,"HeapEnableTermination") or has_api(data,"HeapSetInformation")[0]:
        vals.append({"id":"heap","name":"HeapEnableTerminationOnCorruption","type":"Heap Hardening","status":"BOUNDED"})
    
    if has_in_findings(data,"Bounds","Triple","Double Validation","InputBufferLength"):
        vals.append({"id":"bc","name":"Mehrstufige Bounds-Checks","type":"Size Validation","status":"BOUNDED"})
    
    if hstrsafe:
        vals.append({"id":"fmt","name":"Safe Format-Strings (_s)","type":"Format String Safety","status":"BOUNDED"})
    
    # Default if nothing found
    if not vals:
        if k:
            vals.append({"id":"v0","name":"Kernel-API-Validierung unbekannt","type":"Prüfung empfohlen","status":"UNCHECKED"})
        else:
            vals.append({"id":"v0","name":"User-Mode-Validierung unbekannt","type":"Prüfung empfohlen","status":"UNCHECKED"})
    
    # --- SINKS ---
    hmc,_,ml = has_api(data,"memcpy")
    hmm,_,_ = has_api(data,"memmove")
    hll,_,_ = has_api(data,"LoadLibrary")
    hcp,_,_ = has_api(data,"CreateProcess","ShellExecute")
    hzw,_,_ = has_api(data,"ZwWriteFile","WriteFile")
    hzr,_,_ = has_api(data,"ZwReadFile","ReadFile")
    hre,_,_ = has_api(data,"RegSetValue")
    hbc,_,_ = has_api(data,"BCrypt")
    hmd,_,_ = has_api(data,"MmMapLockedPages","IoBuildPartialMdl","IoAllocateMdl")
    
    if hmc: snks.append({"id":"mc","name":"memcpy","addr":"msvcrt/ucrtbase","risk":"CWE-119" if ml!="low" else ""})
    if hmm: snks.append({"id":"mm","name":"memmove","addr":"msvcrt/ucrtbase","risk":""})
    if hll: snks.append({"id":"ll","name":"LoadLibrary","addr":"kernel32","risk":"CWE-426"})
    if hcp: snks.append({"id":"cp","name":"CreateProcess","addr":"kernel32","risk":"CWE-78"})
    if hzw: snks.append({"id":"zw","name":"Disk Write","addr":"ntoskrnl/kernel32","risk":""})
    if hzr: snks.append({"id":"zr","name":"Disk Read","addr":"ntoskrnl/kernel32","risk":""})
    if hre: snks.append({"id":"re","name":"Registry Write","addr":"advapi32","risk":""})
    if hbc: snks.append({"id":"bc","name":"BCrypt Encrypt/Decrypt","addr":"bcrypt","risk":""})
    if hmd: snks.append({"id":"md","name":"MDL-Mapping","addr":"ntoskrnl","risk":"CWE-119"})
    
    if not snks:
        snks.append({"id":"s0","name":"Keine Sinks via Import identifiziert","addr":"-","risk":""})
    
    # CWE counts from cwe_checker
    cwe787 = has_in_tools(data,"cwe787_oob_write")
    cwe676 = has_in_tools(data,"cwe676_dangerous_func")
    if cwe676: snks.append({"id":"cw","name":f"cwe_checker: CWE676","addr":"Docker-Scan","risk":"MEDIUM"})
    if cwe787: snks.append({"id":"c7","name":f"cwe_checker: CWE787","addr":"Docker-Scan","risk":"MEDIUM"})
    
    # --- BUILD MERMAID ---
    lines = ["graph TD"]
    
    lines.append('  subgraph "Eingabe-Quellen"')
    for s in srcs:
        detail = s.get("detail","")
        lines.append(f'    {s["id"]}["{clean(s["name"])}<br/>{detail}"]')
    lines.append("  end")
    
    lines.append('  subgraph "Validierung / Schutz"')
    for v in vals:
        st = v.get("status","UNCHECKED")
        c = "#00fd00" if st=="BOUNDED" else "#ffc107" if st=="CONDITIONAL" else "#ff8c00"
        lb = clean(v["name"]) + "  " + clean(v["type"])
        lines.append(f'    {v["id"]}{{{{ {lb} }}}}')
        lines.append(f'    style {v["id"]} fill:{c},stroke:#333')
    lines.append("  end")
    
    lines.append('  subgraph "Sinks Gefahren"')
    for s in snks:
        r = s.get("risk","")
        c = "#ff8c00" if r else "#00fd00"
        lines.append(f'    {s["id"]}["{clean(s["name"])}<br/>{s["addr"]}"]')
        if r: lines.append(f'    style {s["id"]} fill:{c},stroke:#333')
    lines.append("  end")
    
    # Edges
    for sv in srcs:
        if vals:
            lines.append(f'    {sv["id"]} --> {vals[0]["id"]}')
    
    for v in vals:
        for s in snks[:4]:  # max 4 sinks to avoid clutter
            lines.append(f'    {v["id"]} --> {s["id"]}')
    
    mm = "\n".join(lines)
    
    return {"sources":srcs,"validators":vals,"sinks":snks,
            "edges":[{"from":srcs[0]["id"] if srcs else "?","to":vals[0]["id"] if vals else snks[0]["id"] if snks else "?","label":"Data Flow","status":"BOUNDED"}],
            "graph_mermaid":mm}

count = 0
for yf in sorted(REPORTS.glob("*.yaml")):
    data = yaml.safe_load(yf.read_text(encoding="utf-8"))
    t = build(data)
    data["taint_graph"] = t
    yf.write_text(yaml.dump(data,allow_unicode=True,default_flow_style=False,sort_keys=False),encoding="utf-8")
    count += 1

print(f"{count} enriched")
