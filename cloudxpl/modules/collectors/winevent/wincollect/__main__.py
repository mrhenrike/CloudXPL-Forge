# Garante que o diretório que contém cli.py e src/ esteja no path (poc-harpia/wincollect)
import os
import sys
_here = os.path.dirname(os.path.abspath(__file__))
_parent = os.path.dirname(_here)
if _parent not in sys.path:
    sys.path.insert(0, _parent)
from cli import main
sys.exit(main())
