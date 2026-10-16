#!/usr/bin/env python3
"""
Phishing Lab - Script ejecutable directo en la raíz del repositorio.
Permite ejecutar `python phishing_lab.py ...` directamente sin necesidad de instalación previa.
"""

import sys
from phishing_lab.cli import main

if __name__ == "__main__":
    sys.exit(main())
