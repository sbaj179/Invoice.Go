from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parent.parent
APP_PY = ROOT / "invoicing_app" / "app.py"

if not APP_PY.exists():
    raise RuntimeError(f"Could not find app.py at expected path: {APP_PY}")

spec = importlib.util.spec_from_file_location("invoicego_app", APP_PY)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not load module spec for: {APP_PY}")

module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

app = getattr(module, "app", None)
if app is None:
    raise RuntimeError(f"Found {APP_PY} but it does not define `app = Flask(...)`")