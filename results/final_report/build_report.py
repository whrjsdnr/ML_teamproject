"""Rebuild the final report from the editable content and verified artifacts."""
import runpy
from pathlib import Path
runpy.run_path(str(Path(__file__).with_name("render_final_report.py")),run_name="__main__")
