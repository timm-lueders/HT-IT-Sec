# Binary Security Audit Pipeline

Multi-LLM Pipeline fur automatisierte Sicherheitsanalyse von Windows-Binaries ohne Source-Code.

## Struktur

```
pipeline/
├── template.yaml                    # Standardisiertes Template fur alle LLMs
├── generate_report.py               # Befullt Template aus GhidraMCP-Daten
├── build_site.py                    # Konvertiert YAML-Reports zu HTML-Website
├── reports/                         # Ein YAML-File pro Binary
│   ├── fvevol.yaml
│   └── cmd.yaml
├── site/                            # Generierte HTML-Website (via build_site.py)
│   ├── index.html
│   ├── fvevol.html
│   └── cmd.html
├── .github/workflows/
│   └── deploy.yml                   # GitHub Actions: Build + Deploy zu Pages
└── README.md
```

## Workflow fur LLMs

```
1. LLM analysiert Binary mit GhidraMCP
2. LLM schreibt Ergebnisse in das YAML-Template
3. YAML-Datei in reports/ speichern
4. Git commit + push
5. GitHub Actions baut Website
6. Deployment auf GitHub Pages (automatisch)
```

## Template befullen

```bash
# Leeres Template erzeugen
python generate_report.py --template-only meine_binary.dll

# Aus GhidraMCP JSON-Daten befullen
python generate_report.py fvevol.sys ./ghidra_data/

# Oder direkt YAML editieren
nano reports/fvevol.yaml
```

## Website lokal bauen

```bash
pip install pyyaml
python build_site.py
# Output: site/index.html + site/*.html
```

## Template-Sektionen

| Sektion | Beschreibung |
|---|---|
| `meta` | Name, Typ, Hashes, Datum, Analyst |
| `binary_info` | Architektur, Entry, Funktionen |
| `pe_security` | ASLR, DEP, CFG, High-Entropy |
| `segments` | Memory-Layout (Code/Data/Init) |
| `import_risk_map` | APIs nach Risiko (HIGH/MEDIUM/LOW/INFO) |
| `irp_handlers` | Kernel-Treiber: IRP-MJ-Handler-Audit |
| `findings` | Schwachstellen mit CWE, Taint-Path, Severity |
| `taint_graph` | User-Input -> Sink Pfade |
| `tools_output` | flawfinder, cwe_checker, GCC-analyzer Ergebnisse |
| `artifacts` | Gepatchte Binaries, Testbenches, C-Dateien |
| `summary` | Risikobewertung, Coverage, Empfehlung |
