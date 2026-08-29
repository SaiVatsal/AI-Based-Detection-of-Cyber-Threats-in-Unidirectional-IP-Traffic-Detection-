import sys
import os
from pathlib import Path

# Add project root to sys.path so 'backend' imports resolve cleanly
root_path = Path(__file__).resolve().parent.parent
if str(root_path) not in sys.path:
    sys.path.insert(0, str(root_path))

from backend.main import app
