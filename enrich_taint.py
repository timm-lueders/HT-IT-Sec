#!/usr/bin/env python3
"""enrich_taint.py - Super-detailed taint graphs for ALL YAML reports."""
import yaml, pathlib

REPORTS = pathlib.Path(r"C:\Users\batar\Desktop\Neuer Ordner\pipeline\HT-IT-Sec\reports")

def clean(s):
    return s.replace("("," ").replace(")"," ").replace("<br/>"," ").replace("<br>"," ")[:50]

def has(data, *kw):
    for lvl in ["high","medium","low","info"]:
        for a in data.get("import_risk_map",{}).get(lvl,[]):
            if any(k in a.get("api","") for k in kw): return True, a.get("api",""), lvl
    return False, "", ""

def build(data):
    nm = data.get("meta",{}).get("binary_name","?")
    k = "kernel" in data.get("meta",{}).get("binary_type","")
    
    srcs = []
    vals = []
    snks = []
    
    if k:
        srcs.append({"id":"ioctl","name":"DeviceIoControl","type":"IOCTL","irp":"Irp->UserBuffer @0x70"})
        srcs.append({"id":"read","name":"IRP_MJ_READ","type":"DIRECT_IO","irp":"Irp->MdlAddress @0x10"})
        srcs.append({"id":"write","name":"IRP_MJ_WRITE","type":"DIRECT_IO","irp":"Irp->MdlAddress @0x10"})
    else:
        srcs.append({"id":"cmd","name":"GetCommandLineW","type":"Args"})
        srcs.append({"id":"con","name":"ReadConsoleW","type":"Input"})
        if "dll" in data.get("meta",{}).get("binary_type",""):
            srcs.append({"id":"com","name":"COM/DCOM","type":"RPC"})
    
    hpw,_,_ = has(data, "ProbeForWrite"); hpr,_,_ = has(data, "ProbeForRead")
    hpm,_,_ = has(data, "ExGetPreviousMode"); hsc,_,_ = has(data, "SeCapture")
    hht,_,_ = has(data, "HeapEnableTermination")
    
    if hpw: vals.append({"id":"pw","name":"ProbeForWrite","type":"Buffer Probe"})
    if hpr: vals.append({"id":"pr","name":"ProbeForRead","type":"Buffer Probe"})
    if hpm: vals.append({"id":"pm","name":"ExGetPreviousMode","type":"Mode Check"})
    if hsc: vals.append({"id":"sc","name":"SeCaptureSubjectContext","type":"Security"})
    if hht: vals.append({"id":"ht","name":"HeapEnableTermination","type":"Heap Hardening"})
    if not vals: vals.append({"id":"v0","name":"Unbekannte Validierung","type":"?"})
    
    hmc,_,_ = has(data,"memcpy"); hmm,_,_ = has(data,"memmove")
    hll,_,_ = has(data,"LoadLibrary"); hcp,_,_ = has(data,"CreateProcess")
    hzw,_,_ = has(data,"ZwWriteFile","WriteFile"); hzr,_,_ = has(data,"ZwReadFile","ReadFile")
    hre,_,_ = has(data,"RegSetValue"); hbc,_,_ = has(data,"BCrypt")
    hmd,_,_ = has(data,"MmMapLockedPages","IoBuildPartialMdl")
    
    if hmc: snks.append({"id":"mc","name":"memcpy","addr":"EXTERNAL","risk":"CWE-119"})
    if hmm: snks.append({"id":"mm","name":"memmove","addr":"EXTERNAL"})
    if hll: snks.append({"id":"ll","name":"LoadLibrary","addr":"EXTERNAL","risk":"CWE-426"})
    if hcp: snks.append({"id":"cp","name":"CreateProcess","addr":"EXTERNAL","risk":"CWE-78"})
    if hzw: snks.append({"id":"zw","name":"ZwWriteFile","addr":"EXTERNAL"})
    if hzr: snks.append({"id":"zr","name":"ZwReadFile","addr":"EXTERNAL"})
    if hre: snks.append({"id":"re","name":"RegSetValue","addr":"EXTERNAL"})
    if hbc: snks.append({"id":"bc","name":"BCryptEncrypt","addr":"EXTERNAL"})
    if hmd: snks.append({"id":"md","name":"MDL-Mapping","addr":"EXTERNAL","risk":"CWE-119"})
    if not snks: snks.append({"id":"s0","name":"Unbekannt","addr":"?"})
    
    # Build Mermaid graph
    lines = ["graph TD"]
    
    lines.append('  subgraph "Quellen Input"')
    for s in srcs: lines.append(f'    {s["id"]}["{clean(s["name"])}"]')
    lines.append("  end")
    
    if len(vals)>1 or vals[0]["id"]!="v0":
        lines.append('  subgraph "Validierung"')
        for v in vals: lines.append(f'    {v["id"]}{{{{{clean(v["name"])}}}}}')
        lines.append("  end")
    
    lines.append('  subgraph "Sinks"')
    for s in snks: lines.append(f'    {s["id"]}["{clean(s["name"])}"]')
    lines.append("  end")
    
    # Edges: sources -> validators -> sinks
    for v in vals:
        st = "BOUNDED" if v["id"]!="v0" else "UNCHECKED"
        lines.append(f'    {srcs[0]["id"]} -->|"{clean(v["type"])}"| {v["id"]}')
    
    for s in snks:
        st = "UNCHECKED" if s.get("risk") else "BOUNDED"
        stl = "-->" if st=="BOUNDED" else "==>"
        last = vals[-1]["id"] if vals else srcs[0]["id"]
        lines.append(f'    {last} {stl}|"{clean(s.get("addr","?"))}"| {s["id"]}')
    
    for s in snks:
        if s.get("risk"): lines.append(f'    style {s["id"]} fill:#ff8c00,stroke:#333')
    
    mm = "\n".join(lines)
    
    return {"sources":srcs,"validators":vals,"sinks":snks,
            "edges":[{"from":srcs[0]["id"],"to":vals[0]["id"] if vals else snks[0]["id"],"label":"Data Flow","status":"BOUNDED"}],
            "graph_mermaid":mm}

count = 0
for yf in sorted(REPORTS.glob("*.yaml")):
    data = yaml.safe_load(yf.read_text(encoding="utf-8"))
    t = build(data)
    data["taint_graph"] = t
    yf.write_text(yaml.dump(data,allow_unicode=True,default_flow_style=False,sort_keys=False),encoding="utf-8")
    count += 1
    print(f"  {data.get('meta',{}).get('binary_name','?'):30s} {len(t['sources'])}S/{len(t['validators'])}V/{len(t['sinks'])}K")

print(f"\n{count} enriched")
