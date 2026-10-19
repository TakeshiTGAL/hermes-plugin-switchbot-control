"""Python 3.9 cannot import this plugin. Hermes runs on 3.11 or newer."""
import sys
from pathlib import Path

if sys.version_info < (3, 10):
    collect_ignore = [
        path.name
        for path in Path(__file__).parent.glob("test_*.py")
        if path.name != "test_python_floor.py"
    ]
