#!/usr/bin/env python3
"""iCopy-X native UI audit. Uses repository's real lib.json_renderer + Tk Canvas.
No PM3 calls. No plugin on_enter execution: those require activity runtime.
"""
import argparse
import csv
import importlib
import json
import os
from pathlib import Path
import re
import sys
import tkinter as tk
from tkinter import font as tkfont

def fail(code, message):
    print(json.dumps({"status": code, "message": str(message)}), file=sys.stderr)
    raise SystemExit(2)

def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("plugin", type=Path, help="Directory containing ui.json")
    p.add_argument("--out", type=Path, default=Path("ui-audit-report"))
    p.add_argument("--references", type=Path, help="Approved reference PNGs, matched by state_EN.png or state_FR.png")
    p.add_argument("--vars", type=Path, help="JSON fixture with UI placeholder values")
    p.add_argument("--strict", action="store_true", help="Fail on errors and reference differences")
    p.add_argument("--threshold", type=float, default=0.03, help="Maximum reference mismatch fraction (0..1)")
    return p.parse_args()

def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        fail("INVALID_JSON", "{}: {}".format(path, e))

def font_metrics(canvas, item):
    try:
        name = canvas.itemcget(item, "font")
        f = tkfont.Font(root=canvas, font=name)
        return {"family": f.actual("family"), "size": f.actual("size"),
                "pixel_width": f.measure(canvas.itemcget(item, "text")),
                "line_height": f.metrics("linespace")}
    except Exception:
        return {}

def snapshot(canvas):
    result = []
    for item in canvas.find_all():
        typ = canvas.type(item)
        bbox = canvas.bbox(item)
        rec = {"id": item, "type": typ, "bbox": list(bbox) if bbox else None,
               "tags": list(canvas.gettags(item))}
        if typ == "text":
            rec.update({"text": canvas.itemcget(item, "text"),
                        "fill": canvas.itemcget(item, "fill"),
                        "anchor": canvas.itemcget(item, "anchor"),
                        "font": canvas.itemcget(item, "font")})
            rec["metrics"] = font_metrics(canvas, item)
        result.append(rec)
    return result

def analyze(items, state, lang):
    findings = []
    for it in items:
        b = it["bbox"]
        if not b:
            continue
        if b[0] < 0 or b[1] < 0 or b[2] > 240 or b[3] > 240:
            findings.append({"severity": "ERROR", "code": "OFFSCREEN",
                             "state": state, "lang": lang, "item": it["id"],
                             "text": it.get("text", ""), "bbox": b})
        if it["type"] == "text" and b[1] < 200 < b[3]:
            findings.append({"severity": "ERROR", "code": "CROSSES_BUTTON_BAR",
                             "state": state, "lang": lang, "item": it["id"],
                             "text": it.get("text", ""), "bbox": b})
    # Text-to-text collisions are a heuristic, not a proof of visual corruption.
    texts = [it for it in items if it["type"] == "text" and it["bbox"] and it.get("text", "").strip()]
    for i, a in enumerate(texts):
        for b in texts[i+1:]:
            x = min(a["bbox"][2], b["bbox"][2]) - max(a["bbox"][0], b["bbox"][0])
            y = min(a["bbox"][3], b["bbox"][3]) - max(a["bbox"][1], b["bbox"][1])
            if x > 3 and y > 3:
                findings.append({"severity": "WARNING", "code": "TEXT_OVERLAP_POSSIBLE",
                                 "state": state, "lang": lang,
                                 "items": [a["id"], b["id"]],
                                 "texts": [a.get("text", ""), b.get("text", "")]})
    return findings

def reference_check(image_path, reference, out, threshold):
    try:
        from PIL import Image, ImageChops
    except ImportError:
        return {"status": "BLOCKED_PILLOW_MISSING"}
    if not reference.exists():
        return {"status": "NO_REFERENCE"}
    if not image_path.exists():
        return {"status": "NO_RENDER_IMAGE"}
    a = Image.open(reference).convert("RGB").resize((240, 240))
    b = Image.open(image_path).convert("RGB").resize((240, 240))
    import numpy as np
    delta = np.asarray(ImageChops.difference(a, b))
    mismatch = float(np.mean(np.max(delta, axis=2) > 24))
    ImageChops.difference(a, b).save(out)
    return {"status": "PASS" if mismatch <= threshold else "DIFFERENCE",
            "different_fraction": round(mismatch, 6), "threshold": threshold}

def export_png(canvas, output):
    # Native Tk PostScript. Ghostscript converts to PNG; never fake success.
    import shutil
    import subprocess
    if not shutil.which("gs"):
        return False, "Ghostscript unavailable"
    ps = output.with_suffix(".ps")
    canvas.postscript(file=str(ps), colormode="color", pagewidth="240p", pageheight="240p")
    cmd = ["gs", "-q", "-dSAFER", "-dBATCH", "-dNOPAUSE", "-sDEVICE=png16m",
           "-r72", "-sOutputFile="+str(output), str(ps)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    ps.unlink(missing_ok=True)
    return proc.returncode == 0, proc.stderr[-400:]

def main():
    args = parse_args()
    plugin = args.plugin.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    if not (plugin/"ui.json").exists():
        fail("MISSING_UI", plugin/"ui.json")
    ui = read_json(plugin/"ui.json")
    manifest = read_json(plugin/"manifest.json") if (plugin/"manifest.json").exists() else {}
    fr_path = plugin/"lang"/"fr.json"
    fr = read_json(fr_path) if fr_path.exists() else {}
    values = read_json(args.vars) if args.vars else {
        "uid_count": 1, "uid_count_label": "1 UID", "uid": "1234567890",
        "uid1": "1234567890", "uid2": "1234567891", "uid3": "1234567892",
        "error_msg": "Tag not detected", "block_num": 2,
        "hex_value": "1234567890", "dec_value": "78187493520"
    }
    repo_src = Path(__file__).resolve().parents[2]/"src"
    if not (repo_src/"lib"/"json_renderer.py").exists():
        fail("NATIVE_RENDERER_MISSING", repo_src)
    sys.path.insert(0, str(repo_src))
    try:
        from lib.json_renderer import JsonRenderer
        from lib import resources
    except Exception as e:
        fail("NATIVE_IMPORT_FAILED", repr(e))
    root = tk.Tk()
    root.withdraw()
    canvas = tk.Canvas(root, width=240, height=240, highlightthickness=0)
    canvas.pack()
    root.update_idletasks()
    states = ui.get("states", {})
    if not isinstance(states, dict):
        fail("BAD_UI_SCHEMA", "states must be an object")
    findings, cases = [], []
    if manifest.get("version") != ui.get("version"):
        findings.append({"severity":"ERROR","code":"VERSION_MISMATCH",
                         "manifest":manifest.get("version"),"ui":ui.get("version")})
    for state, definition in states.items():
        if not isinstance(definition, dict) or not isinstance(definition.get("screen"), dict):
            findings.append({"severity":"WARNING","code":"NO_SCREEN","state":state})
            continue
        screen = definition["screen"]
        for lang in ("EN","FR"):
            canvas.delete("all")
            renderer = JsonRenderer(canvas)
            renderer.set_state(values)
            if lang == "FR":
                renderer.set_translator(lambda text: fr.get(text, text))
            try:
                renderer.render(screen)
                root.update_idletasks()
                items = snapshot(canvas)
                issues = analyze(items, state, lang)
                findings.extend(issues)
                if definition.get("on_enter"):
                    findings.append({"severity":"INFO","code":"ON_ENTER_NOT_EXECUTED",
                                     "state":state,"lang":lang,"action":definition["on_enter"]})
                image_path = args.out/("{}_{}.png".format(state,lang))
                ok, detail = export_png(canvas, image_path)
                if not ok:
                    findings.append({"severity":"WARNING","code":"PNG_EXPORT_FAILED",
                                     "state":state,"lang":lang,"detail":detail})
                ref = (args.references/"{}_{}.png".format(state,lang)) if args.references else None
                comparison = reference_check(image_path,ref,
                    args.out/("{}_{}_diff.png".format(state,lang)),args.threshold) if ref else {"status":"NOT_REQUESTED"}
                if comparison["status"] == "DIFFERENCE":
                    findings.append({"severity":"ERROR","code":"REFERENCE_DIFFERENCE",
                                     "state":state,"lang":lang,"fraction":comparison["different_fraction"]})
                cases.append({"state":state,"lang":lang,"items":items,"reference":comparison})
            except Exception as e:
                findings.append({"severity":"ERROR","code":"RENDER_EXCEPTION",
                                 "state":state,"lang":lang,"message":repr(e)})
    # Validate static placeholder references and state transitions without running RF.
    tokens = set()
    for state, definition in states.items():
        if not isinstance(definition,dict):continue
        screen = definition.get("screen",{})
        tokens.update(re.findall(r"\{([A-Za-z_]\w*)\}",json.dumps(screen)))
        for action in list(screen.get("keys",{}).values())+list(definition.get("transitions",{}).values()):
            if isinstance(action,str) and action.startswith("set_state:"):
                target = action.partition(":")[2]
                if target not in states:
                    findings.append({"severity":"ERROR","code":"INVALID_STATE_TARGET",
                                     "state":state,"target":target})
    for token in sorted(tokens-set(values)):
        findings.append({"severity":"WARNING","code":"UNRESOLVED_FIXTURE_TOKEN","token":token})
    (args.out/"report.json").write_text(json.dumps(
        {"plugin":str(plugin),"native_renderer":"lib.json_renderer.JsonRenderer",
         "limitations":["PluginActivity lifecycle not executed","on_enter not executed",
                        "Native input widgets not executed","Hardware not simulated"],
         "cases":cases,"findings":findings},ensure_ascii=False,indent=2),encoding="utf-8")
    with (args.out/"findings.csv").open("w",newline="",encoding="utf-8") as fh:
        writer=csv.writer(fh);writer.writerow(["severity","code","state","lang","details"])
        for finding in findings:
            writer.writerow([finding.get(k,"") for k in ("severity","code","state","lang")]+[json.dumps(finding,ensure_ascii=False)])
    count={s:sum(f["severity"]==s for f in findings) for s in ("ERROR","WARNING","INFO")}
    (args.out/"SUMMARY.md").write_text(
        "# iCopy-X native UI audit\n\nPlugin: `{}`\n\nRendered cases: {}\n\nErrors: {} | Warnings: {} | Info: {}\n\n"
        "Renderer: real repository `lib.json_renderer.JsonRenderer`. "
        "Not a hardware or full PluginActivity test. "
        "Review `report.json` and `findings.csv` for exact text, bboxes and font metrics.\n"
        .format(plugin,len(cases),count["ERROR"],count["WARNING"],count["INFO"]),encoding="utf-8")
    print(json.dumps({"status":"COMPLETE_NATIVE_JSON_RENDERER_AUDIT","cases":len(cases),
                      "counts":count,"report":str(args.out/"report.json")}))
    root.destroy()
    if args.strict and count["ERROR"]:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
