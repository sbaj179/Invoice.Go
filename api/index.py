import os
import importlib.util

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Try common layouts (pick the first that exists)
CANDIDATES = [
    os.path.join(ROOT, "invoicing_app", "app.py"),
    os.path.join(ROOT, "invoicing_app", "invoicing_app", "app.py"),
    os.path.join(ROOT, "app.py"),
]

APP_PY = next((p for p in CANDIDATES if os.path.exists(p)), None)
if not APP_PY:
    raise RuntimeError(
        "Could not find app.py. Looked in:\n" + "\n".join(CANDIDATES)
    )

spec = importlib.util.spec_from_file_location("flaskapp", APP_PY)
mod = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(mod)

# Your Flask instance inside app.py must be named `app`
app = getattr(mod, "app", None)
if app is None:
    raise RuntimeError(f"Found {APP_PY} but it does not define `app = Flask(...)`")