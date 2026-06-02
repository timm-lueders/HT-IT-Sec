#!/usr/bin/env python3
"""
build_site.py -- YAML Reports zu Terminal-Style HTML-Website
Holy-Grail-Layout, Grun-auf-Schwarz, Flicker-Effekt, Blink-Cursor
"""
import yaml, os
from datetime import datetime
from pathlib import Path

REPORTS_DIR = Path("reports")
OUTPUT_DIR = Path("site")

SEVERITY_COLORS = {
    "CRITICAL": "#ff3333", "HIGH": "#ff8c00", "MEDIUM": "#ffd700",
    "LOW": "#00fd00", "INFO": "#888888", "OK": "#00fd00"
}

CSS = """
*{margin:0;padding:0;box-sizing:border-box}
html{
  background:#212121 url(background.gif) left top/10.8% 10.8% repeat;
  background-blend-mode:overlay;
  color:#00fd00;
  font-family:"Terminal",sans-serif,monospace;
  -webkit-font-smoothing:antialiased;
  -moz-osx-font-smoothing:grayscale;
  text-rendering:optimizeLegibility;
}
body{
  display:grid;
  grid-template-columns:100px 1fr 100px;
  grid-template-rows:auto 1fr auto;
  gap:1rem;
  min-height:100vh;
}
header{
  grid-column:1/4;
  background:gray;
  padding:20px 30px;
  margin:10px;
  border-radius:2rem;
  box-shadow:10px 10px 15px black;
  display:flex;
  align-items:center;
  justify-content:space-between;
  flex-wrap:wrap;
}
header h1{
  font-size:1.5rem;
  margin:0;
}
header nav a{
  color:#a4c574;
  text-decoration:none;
  margin-left:20px;
  font-size:0.95rem;
}
header nav a:hover{text-decoration:underline;color:#00fd00}
header .stats{font-size:0.85rem;color:#aaa}
main{
  padding:20px;
  text-shadow:0 0 3px rgba(0,0,0,1),0 0 20px rgba(0,253,0,0.6);
  mix-blend-mode:lighten;
  animation:flicker 0.3s infinite;
}
@keyframes flicker{
  0%,50%,100%{opacity:0.92}
  25%,75%{opacity:1}
}
footer{
  grid-column:1/4;
  text-align:center;
  background:gray;
  padding:15px 10px;
  margin:10px;
  border-radius:2rem;
  box-shadow:inset 10px 10px 15px black;
  font-size:0.8rem;
}
aside{min-height:50px}
h1,h2,h3{color:#00fd00}
h1:hover{cursor:pointer}
h2{margin:25px 0 15px;border-bottom:1px dashed #00fd00;padding-bottom:8px}
h3{margin:15px 0 10px;color:#a4c574}
a{color:#a4c574;text-decoration:none}
a:hover{text-decoration:underline;color:#00fd00}
hr{border-style:dashed;border-color:#00fd00;box-shadow:0 0 3px rgba(0,0,0,1),0 0 10px rgba(0,253,0,0.6);margin:25px 0}
table{width:100%;border-collapse:collapse;margin:10px 0}
th,td{text-align:left;padding:10px 14px;border-bottom:1px dashed #333}
th{color:#aaa;font-size:0.85rem;text-transform:uppercase;letter-spacing:1px}
td{font-size:0.9rem}
tr:hover{background:rgba(0,253,0,0.05)}
.card{
  background:rgba(0,0,0,0.3);
  border:1px solid #333;
  border-radius:8px;
  padding:18px;
  margin:15px 0;
}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.grid4{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:bold;text-transform:uppercase;letter-spacing:1px}
.sev-CRITICAL{background:#ff3333;color:#000}
.sev-HIGH{background:#ff8c00;color:#000}
.sev-MEDIUM{background:#ffd700;color:#000}
.sev-LOW{background:#00fd00;color:#000}
.sev-INFO{background:#444;color:#aaa}
.sev-OK{background:#00fd00;color:#000}
.finding{border-left:4px solid #ffd700;padding-left:18px;margin:18px 0}
.finding-CRITICAL{border-left-color:#ff3333}
.finding-HIGH{border-left-color:#ff8c00}
.finding-MEDIUM{border-left-color:#ffd700}
.finding-LOW{border-left-color:#00fd00}
.finding-info{margin-top:8px;font-size:0.85rem;color:#888}
.progress-bar{
  background:#333;
  border-radius:8px;
  height:10px;
  margin:5px 0;
  overflow:hidden;
}
.progress-fill{
  height:100%;
  border-radius:8px;
  background:#00fd00;
  box-shadow:0 0 8px rgba(0,253,0,0.5);
}
.risk-LOW .progress-fill{background:#00fd00}
.risk-MEDIUM .progress-fill{background:#ffd700}
.risk-HIGH .progress-fill{background:#ff8c00}
.risk-CRITICAL .progress-fill{background:#ff3333}
.cursor{
  display:inline-block;
  width:12px;height:2px;
  background:#00fd00;
  animation:blink 0.8s infinite;
  vertical-align:middle;margin-left:2px;
}
@keyframes blink{0%,100%{opacity:0}50%{opacity:1}}
.file-list{font-family:monospace;font-size:0.85rem;color:#a4c574;margin:10px 0}
.file-list span{padding:2px 8px}
pre{background:rgba(0,0,0,0.5);border:1px solid #333;border-radius:6px;padding:12px;overflow-x:auto;font-size:0.8rem;color:#a4c574}
@media(max-width:768px){
  body{grid-template-columns:1fr;margin:5px}
  header,footer{grid-column:1;margin:5px}
  aside{display:none}
  .grid2{grid-template-columns:1fr}
}
"""

INDEX_CSS_EXTRA = """
.binary-row{cursor:pointer}
.binary-row:hover{background:rgba(0,253,0,0.08)}
.count{font-size:1.2rem;font-weight:bold}
"""

def load_reports():
    reports = []
    for f in sorted(REPORTS_DIR.glob("*.yaml")):
        with open(f, encoding="utf-8") as fp:
            d = yaml.safe_load(fp)
            d["_file"] = f.stem
            if not d.get("meta"): d["meta"] = {}
            if not d.get("binary_info"): d["binary_info"] = {}
            if not d.get("pe_security"): d["pe_security"] = {}
            if not d.get("summary"): d["summary"] = {}
            if not d.get("findings"): d["findings"] = []
            if not d.get("tools_output"): d["tools_output"] = {}
            if not d.get("artifacts"): d["artifacts"] = []
            if not d.get("import_risk_map"): d["import_risk_map"] = {}
            reports.append(d)
    return reports

def sev_badge(sev):
    return f'<span class="badge sev-{sev}">{sev}</span>'

def pe_section(d):
    p = d["pe_security"]
    items = [
        ("ASLR", p.get("aslr")), ("DEP/NX", p.get("dep")),
        ("CFG", p.get("cfg")), ("High-Entropy", p.get("high_entropy_aslr"))
    ]
    rows = "".join(
        f'<div>{"OK" if v else "FEHLT"} <span style="color:#888;font-size:0.8rem">{name}</span></div>'
        for name, v in items
    )
    notes = p.get("notes", "")
    return f'<div class="card"><h3>PE Security</h3><div class="grid4">{rows}</div>{"<p style=\"margin-top:8px;font-size:0.85rem;color:#888\">"+notes+"</p>" if notes else ""}</div>'

def findings_section(d):
    fl = d["findings"]
    if not fl: return '<div class="card"><h3>Findings</h3><p style="color:#888">Keine Findings.</p></div>'
    rows = []
    for f in fl:
        sev = f.get("severity", "INFO")
        rows.append(f"""<div class="finding finding-{sev}">
        {sev_badge(sev)} <b>{f.get('cwe','')}: {f.get('title','')}</b>
        <p style="margin-top:6px;font-size:0.9rem">{f.get('description','')}</p>
        <div class="finding-info">Funktion: {f.get('function','?')} @ {f.get('address','?')}<br>
        Taint-Path: {f.get('taint_path','-')}<br>
        Empfehlung: {f.get('recommendation','-')}</div></div>""")
    return f'<div class="card"><h3>Findings ({len(fl)})</h3>{"".join(rows)}</div>'

def tools_section(d):
    t = d["tools_output"]
    fl = t.get("flawfinder", {})
    cw = t.get("cwe_checker", {})
    gc = t.get("gcc_analyzer", {})
    return f"""<div class="card"><h3>Automatisierte Tools</h3>
    <table>
    <tr><td>flawfinder</td><td>L3: {fl.get('level_3_hits',0)} / L4: {fl.get('level_4_hits',0)} / L5: {fl.get('level_5_hits',0)}</td></tr>
    <tr><td>cwe_checker</td><td>{cw.get('total_findings',0)} Findings (~{cw.get('estimated_false_positive_rate',97)}% FP)</td></tr>
    <tr><td>GCC -fanalyzer</td><td>{'OK' if gc.get('compiled') else 'N/A'} ({gc.get('tests_passed',0)} Pass / {gc.get('tests_failed',0)} Fail)</td></tr>
    </table></div>"""

def import_section(d):
    levels = [("high","HIGH"), ("medium","MEDIUM"), ("low","LOW"), ("info","INFO")]
    rows = ""
    for key, label in levels:
        for api in d.get("import_risk_map", {}).get(key, []):
            rows += f"<tr><td>{sev_badge(label)} {api.get('api','?')}</td><td>{api.get('risk','')}</td><td>{api.get('cwe','')}</td></tr>"
    if not rows: return ""
    return f'<div class="card"><h3>Import Risk Map</h3><table><tr><th>API</th><th>Risiko</th><th>CWE</th></tr>{rows}</table></div>'

def summary_section(d):
    s = d["summary"]; m = d["meta"]
    f = d["findings"]
    sevs = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for x in f: sevs[x.get("severity","INFO")] = sevs.get(x.get("severity","INFO"),0) + 1
    total = sum(sevs.values())
    risk = s.get("overall_risk", "INFO")
    return f"""<div class="card"><h3>Zusammenfassung<span class="cursor"></span></h3>
    <div class="grid2">
    <div><b>Risiko:</b> {sev_badge(risk)}</div>
    <div><b>Analyse-Datum:</b> {m.get('analysis_date','?')}</div>
    <div><b>Funktionen:</b> {d['binary_info'].get('function_count',0)}</div>
    <div><b>Coverage:</b> {s.get('coverage_percent',0)}%</div>
    <div><b>Analyst:</b> {m.get('analyst','?')}</div>
    <div><b>Dauer:</b> {m.get('analysis_duration_minutes',0)} min</div>
    </div>
    <hr>
    <div class="grid4">
    <div>CRITICAL<br><span class="count">{sevs['CRITICAL']}</span></div>
    <div>HIGH<br><span class="count">{sevs['HIGH']}</span></div>
    <div>MEDIUM<br><span class="count">{sevs['MEDIUM']}</span></div>
    <div>LOW<br><span class="count">{sevs['LOW']}</span></div>
    </div>
    <hr>
    <div class="progress-bar risk-{risk}"><div class="progress-fill" style="width:{s.get('coverage_percent',0)}%"></div></div>
    <p style="margin-top:8px;font-size:0.85rem">{s.get('recommendation','')}</p></div>"""

def artifacts_section(d):
    arts = d.get("artifacts", [])
    if not arts: return ""
    rows = "".join(f"<tr><td style='font-family:monospace'>{a.get('file','?')}</td><td>{a.get('type','?')}</td><td style='color:#888'>{a.get('description','')}</td></tr>" for a in arts)
    return f'<div class="card"><h3>Artefakte</h3><table><tr><th>Datei</th><th>Typ</th><th>Beschreibung</th></tr>{rows}</table></div>'

def handlers_section(d):
    handlers = d.get("irp_handlers", [])
    if not handlers: return ""
    rows = "".join(
        f"<tr><td>{h.get('irp_code','?')}</td><td style='font-family:monospace'>{h.get('address','?')}</td><td>{h.get('function_name','?')}</td><td>{h.get('buffer_type','?')}</td><td>{sev_badge(h.get('risk','OK'))}</td></tr>"
        for h in handlers
    )
    return f'<div class="card"><h3>IRP Handler Audit</h3><table><tr><th>IRP Code</th><th>Adresse</th><th>Funktion</th><th>Buffer-Typ</th><th>Risiko</th></tr>{rows}</table></div>'

def taint_section(d):
    tg = d.get("taint_graph", {})
    if not tg: return ""
    srcs = "".join(f"<tr><td>Source</td><td>{s.get('name','?')}</td><td>{s.get('type','?')}</td></tr>" for s in tg.get("sources",[]))
    snks = "".join(f"<tr><td>Sink</td><td>{s.get('name','?')}</td><td>{s.get('address','?')}</td></tr>" for s in tg.get("sinks",[]))
    edges = "".join(
        f"<tr><td>{'BOUNDED' if e.get('bounded') else 'UNCHECKED'}</td><td>{e.get('from','?')}</td><td>{e.get('to','?')}</td><td>{e.get('check_location','-')}</td></tr>"
        for e in tg.get("edges",[])
    )
    return f"""<div class="card"><h3>Taint-Graph</h3>
    <table><tr><th>Typ</th><th>Name</th><th>Detail</th></tr>{srcs}{snks}</table>
    {"<hr><table><tr><th>Status</th><th>Von</th><th>Nach</th><th>Check</th></tr>"+edges+"</table>" if edges else ""}
    </div>"""

def build_detail(report):
    name = report["meta"].get("binary_name", report["_file"])
    m = report["meta"]; bi = report["binary_info"]
    content = f"""<div class="card">
    <div class="grid4">
    <div><b>Typ:</b> {m.get('binary_type','?')}</div>
    <div><b>Arch:</b> {bi.get('architecture','?')}</div>
    <div><b>Entry:</b> <span style="font-family:monospace">{bi.get('entry_point','?')}</span></div>
    <div><b>GroBe:</b> {m.get('file_size_bytes',0):,} bytes</div>
    <div><b>MD5:</b> <span style="font-family:monospace;font-size:0.75rem">{m.get('md5','?')}</span></div>
    <div><b>Funktionen:</b> {bi.get('function_count',0)}</div>
    </div></div>"""
    content += pe_section(report)
    content += import_section(report)
    content += handlers_section(report)
    content += taint_section(report)
    content += tools_section(report)
    content += findings_section(report)
    content += artifacts_section(report)
    content += summary_section(report)
    page = PAGE.replace("{title}", name).replace("{name}", name).replace("{content}", content).replace("{date}", datetime.now().strftime("%Y-%m-%d %H:%M"))
    return page

PAGE = """<!DOCTYPE html><html lang="de">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<link href="http://fonts.cdnfonts.com/css/terminal" rel="stylesheet">
<link rel="icon" type="image/x-icon" href="favicon.ico">
<title>""" + "{title}" + """ -- Security Audit</title>
<style>""" + CSS + """</style>
</head>
<body>
<header>
<h1>""" + "{name}" + """</h1>
<nav><a href="index.html">[Ubersicht]</a></nav>
</header>
<aside></aside>
<main>""" + "{content}" + """</main>
<aside></aside>
<footer>Binary Security Audit Pipeline v1.0 -- """ + "{date}" + """ -- <span class="cursor"></span></footer>
</body></html>"""

def build_index(reports):
    rows = ""
    for d in reports:
        m = d["meta"]; s = d["summary"]; bi = d["binary_info"]
        f = d["findings"]
        sevs = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
        for x in f: sevs[x.get("severity","INFO")] = sevs.get(x.get("severity","INFO"),0)+1
        risk = s.get("overall_risk","INFO")
        total_f = sum(sevs.values())
        rows += f"""<tr class="binary-row" onclick="location.href='{d['_file']}.html'">
        <td><a href="{d['_file']}.html">{m.get('binary_name',d['_file'])}</a></td>
        <td>{m.get('binary_type','?')}</td>
        <td style="font-family:monospace">{bi.get('architecture','?')}</td>
        <td>{sev_badge(risk)}</td>
        <td>C:{sevs['CRITICAL']} H:{sevs['HIGH']} M:{sevs['MEDIUM']} L:{sevs['LOW']}</td>
        <td style="font-size:0.8rem;color:#888">{m.get('analysis_date','?')}</td></tr>"""
    
    html = """<!DOCTYPE html><html lang="de">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<link href="http://fonts.cdnfonts.com/css/terminal" rel="stylesheet">
<link rel="icon" type="image/x-icon" href="favicon.ico">
<title>Binary Security Audit -- Ubersicht</title>
<style>""" + CSS + INDEX_CSS_EXTRA + """</style>
</head><body>
<header><h1>Binary Security Audit Pipeline<span class="cursor"></span></h1>
<nav><span class="stats">""" + str(len(reports)) + """ Binaries analysiert</span></nav></header>
<aside></aside>
<main>
<div class="card"><h3>Ubersicht</h3>
<table><tr><th>Binary</th><th>Typ</th><th>Arch</th><th>Risiko</th><th>Findings (C/H/M/L)</th><th>Datum</th></tr>
""" + rows + """</table></div>
</main><aside></aside>
<footer>Pipeline v1.0 -- """ + datetime.now().strftime('%Y-%m-%d %H:%M') + """ -- <span class="cursor"></span></footer>
</body></html>"""
    return html

def copy_static():
    """Kopiert statische Assets (background, favicon) falls vorhanden."""
    import shutil
    for f in ["background.gif", "favicon.ico"]:
        src = Path(__file__).parent / f
        if src.exists():
            shutil.copy(src, OUTPUT_DIR / f)

def main():
    OUTPUT_DIR.mkdir(exist_ok=True)
    reports = load_reports()
    for d in reports:
        (OUTPUT_DIR / f"{d['_file']}.html").write_text(build_detail(d), encoding="utf-8")
    (OUTPUT_DIR / "index.html").write_text(build_index(reports), encoding="utf-8")
    copy_static()
    print(f"OK: {len(reports)} Detailseiten + index.html in {OUTPUT_DIR}/")

if __name__ == "__main__":
    main()
