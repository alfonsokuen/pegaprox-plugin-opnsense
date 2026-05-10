"""Shared pytest fixtures for the OPNsense plugin tests."""
import os
import sys

# Allow `import opnsense_plugin` style imports without installing.
PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, PLUGIN_ROOT)
