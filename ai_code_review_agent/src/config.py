"""Central configuration."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KB_DIR = ROOT / "kb"
DATA_DIR = ROOT / "data"
SAMPLES_DIR = ROOT / "samples"
INDEX_PATH = DATA_DIR / "kb_index.pkl"

MAX_CODE_BYTES = 200_000
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-5-5")

# Quality thresholds (Code Analysis Agent)
MAX_FUNC_LINES = 50
MAX_COMPLEXITY = 10
MAX_NESTING = 4
MAX_PARAMS = 5
MAX_CLASS_METHODS = 15
MAX_LINE_LEN = 120
