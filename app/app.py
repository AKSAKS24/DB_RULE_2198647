from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional
import re, json

app = FastAPI(title="ABAP Scanner - SAP Note 2198647")

# --- Definitions ---
SQL_TABLES = {"VBUK": "VBAK", "VBUP": "VBAP"}   # tables to check
SQL_FIELDS = {"VBTYP_EXT"}                      # SQL-only field
DECL_FIELDS = {"VBTYP": "VBTYPL"}               # declaration changed element
DECL_FIELDS_OBS = {"VBTYP_EXT"}                 # declaration obsolete field

# Regex
SQL_SELECT_BLOCK_RE = re.compile(
    r"\bSELECT\b(?P<select>.+?)\bFROM\b\s+(?P<table>\w+)(?P<rest>.*?)(?=(\bSELECT\b|$))",
    re.IGNORECASE | re.DOTALL,
)
JOIN_RE = re.compile(r"\bJOIN\s+(?P<table>\w+)", re.IGNORECASE)

DECLARATION_RE = re.compile(
    r"\b(?:TYPE|LIKE)\b\s+(?P<field>[A-Z0-9_]+)", re.IGNORECASE
)

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = None
    code: Optional[str] = ""

# --- Comment helpers ---
def comment_table(tbl: str) -> str:
    return f"* TODO: Table {tbl.upper()} obsolete in S/4HANA (Note 2198647). Replace with {SQL_TABLES[tbl]}."

def comment_decl_field(field: str) -> str:
    f = field.upper()
    if f in DECL_FIELDS_OBS:
        return f"* TODO: Field {f} obsolete (Note 2198647). Remove usage."
    if f in DECL_FIELDS:
        return f"* TODO: Data element {f} was lengthened (Note 2198647). Use {DECL_FIELDS[f]}."
    return ""

def comment_sql_field(f: str) -> str:
    return f"* TODO: Field {f} obsolete (Note 2198647). Remove usage."

# --- SQL scanner ---
def scan_sql(code: str):
    results=[]
    for stmt in SQL_SELECT_BLOCK_RE.finditer(code):
        table=stmt.group("table").upper()
        rest_text=stmt.group("rest")
        span = stmt.span()

        # check main FROM table
        if table in SQL_TABLES:
            results.append({
                "target_type":"TABLE",
                "target_name":table,
                "field":None,
                "span":stmt.span(),
                "used_fields":[table],
                "suggested_fields":[SQL_TABLES[table]],
                "suggested_statement":comment_table(table)
            })

        # also check JOIN tables
        for jm in JOIN_RE.finditer(rest_text):
            jtable = jm.group("table").upper()
            if jtable in SQL_TABLES:
                results.append({
                    "target_type":"TABLE",
                    "target_name":jtable,
                    "field":None,
                    "span":jm.span(),
                    "used_fields":[jtable],
                    "suggested_fields":[SQL_TABLES[jtable]],
                    "suggested_statement":comment_table(jtable)
                })

        # check SQL field VBTYP_EXT (only once per SELECT block)
        if re.search(r"\bVBTYP_EXT\b", stmt.group(0), re.IGNORECASE):
            results.append({
                "target_type":"SQL_FIELD",
                "target_name":"VBTYP_EXT",
                "field":"VBTYP_EXT",
                "span":span,
                "used_fields":["VBTYP_EXT"],
                "suggested_fields":None,
                "suggested_statement":comment_sql_field("VBTYP_EXT")
            })
    return results

# --- Declaration scanner ---
def scan_declarations(code: str):
    results=[]
    for m in DECLARATION_RE.finditer(code):
        fld=m.group("field").upper()
        if fld in DECL_FIELDS or fld in DECL_FIELDS_OBS:
            results.append({
                "target_type":"DECLARATION",
                "target_name":fld,
                "field":fld,
                "span":m.span(),
                "used_fields":[fld],
                "suggested_fields":([DECL_FIELDS[fld]] if fld in DECL_FIELDS else None),
                "suggested_statement":comment_decl_field(fld)
            })
    return results

# --- API ---
@app.post("/assess-2198647")
def assess(units: List[Unit]):
    results=[]
    for u in units:
        src=u.code or ""
        findings=[]
        seen=set()
        for hit in scan_sql(src)+scan_declarations(src):
            key=(hit["target_type"], hit["target_name"], hit["span"])
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "table":hit["target_name"] if hit["target_type"]=="TABLE" else None,
                "field":hit.get("field"),
                "target_type":hit["target_type"],
                "target_name":hit["target_name"],
                "start_char_in_unit":hit["span"][0],
                "end_char_in_unit":hit["span"][1],
                "used_fields":hit["used_fields"],
                "ambiguous":False,
                "suggested_fields":hit["suggested_fields"],
                "suggested_statement":hit["suggested_statement"]
            })
        obj=json.loads(u.model_dump_json()); obj["selects"]=findings
        results.append(obj)
    return results

@app.get("/health")
def health(): 
    return {"ok":True,"note":"2198647"}