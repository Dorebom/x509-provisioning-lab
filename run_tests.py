"""Run test suite from extracted ZIP without setuptools."""
import os
from pathlib import Path
import sys
import unittest
root = Path(__file__).resolve().parent
src = str(root / 'src')
sys.path.insert(0, src)
os.environ['PYTHONPATH'] = src + (os.pathsep + os.environ['PYTHONPATH'] if os.environ.get('PYTHONPATH') else '')
if __name__ == '__main__':
    suite = unittest.defaultTestLoader.discover(str(root / 'tests'), pattern='test_*.py')
    ok = unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful()
    raise SystemExit(0 if ok else 1)
