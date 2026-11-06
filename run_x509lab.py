"""Run directly after extracting the source ZIP; editable install is not required."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from x509_provisioning_lab.cli import main
if __name__ == '__main__':
    raise SystemExit(main())
