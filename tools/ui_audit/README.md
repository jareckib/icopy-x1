# Native iCopy-X Plugin Screen Audit

This reusable tool audits **any JSON-driven plugin** under `plugins/` using the
**actual repository** `src/lib/json_renderer.py`, `src/lib/resources.py`,
`src/lib/_constants.py` and a real **Tkinter Canvas** under Xvfb.
It does not substitute a hand-drawn imitation of the JSON renderer.

## Run locally

```bash
sudo apt-get install -y xvfb python3-tk ghostscript fonts-dejavu-core
python -m pip install Pillow numpy
xvfb-run -a python tools/ui_audit/native_screen_audit.py plugins/T5577_multiwriter --out ui-audit-report
```

For comparison with approved PNGs, name references
`<state>_EN.png` and `<state>_FR.png` (state = the actual key in `ui.json`).
Then run:

```bash
xvfb-run -a python tools/ui_audit/native_screen_audit.py plugins/T5577_multiwriter \
  --references path/to/approved --out ui-audit-report --strict
```

You may provide `--vars fixture.json` for realistic placeholder values
and `--threshold 0.03` to adjust the fraction of changed pixels tolerated.

## Run on GitHub

Go to **Actions → Plugin native UI audit → Run workflow**.
Set the plugin path, optionally the references path, and strict mode.
Download the `native-ui-audit` artifact when the run finishes.

## Reports

- `report.json`: all drawn Tk Canvas objects, bounding boxes, font
  family/size, measured width, colors, state and language.
- `findings.csv`: precise warnings/errors to fix.
- `SUMMARY.md`: result totals.
- `<state>_<lang>.png`: rendered image.
- `<state>_<lang>_diff.png`: differences from approved PNG, if available.

## Current test scope and limits

Checks: UI/manifest version consistency, native JSON render exceptions,
content outside 240×240, text crossing bottom bar, potential overlapping
text, unresolved fixture tokens, broken `set_state:` targets, English and
French states, and pixel difference from approved images.

**Not yet covered by this tool:** plugin `on_enter` drawing, BaseActivity
top title-bar lifecycle, full PluginActivity key transitions, dynamic
FreeDecInput/FreeHexInput widgets, blinking text, worker threads,
RF/PM3, or real hardware. These are explicitly marked as limitations
in the JSON report. A PASS here is **not** a physical-device PASS and
does not certify a complete visual match when dynamic drawing is used.

A reference directory containing numbered files like `01_EN.png` does
not automatically map to state names. Provide a named copy or a mapping
before interpreting reference comparisons. Do not rename approved
reference assets in place.

This test is intentionally reusable; do not modify core iCopy-X firmware
files to accommodate a particular plugin. The repo's source files retain
their original license and notices.
