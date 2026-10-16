"""
Punto de ejecución de módulo `python -m phishing_lab`.
"""

import sys
from phishing_lab.cli import main

if __name__ == "__main__":
    sys.exit(main())
