
from pathlib import Path
import os

def _resolve_root() -> Path:
    """
    Use repo root by default (parent of the t17/ folder).
    Allow override via env var T17_ROOT if needed.
    """
    env = os.environ.get("T17_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    return Path(__file__).resolve().parents[1]

# ----- Root & standard dirs -----
ROOT_DIR = _resolve_root()
DATA_DIR = ROOT_DIR / "data"
CONFIGS_DIR = ROOT_DIR / "configs"
DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIGS_DIR.mkdir(parents=True, exist_ok=True)

# ----- Standard files -----
MEMORY_PATH = DATA_DIR / "memory.json"
FEEDBACK_LOG_PATH = DATA_DIR / "feedback_log.json"
PROMPTS_PATH = CONFIGS_DIR / "prompt_templates.json"

# ----- Tunables / constants -----
SIMILARITY_THRESHOLD = 0.6
DEFAULT_TIMEOUT = 60

# Helpers (optional)
def data_path(*parts: str) -> Path:
    return DATA_DIR.joinpath(*parts)

def configs_path(*parts: str) -> Path:
    return CONFIGS_DIR.joinpath(*parts)
