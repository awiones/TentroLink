"""
TentroLink Assets Package
------------------------
Contains attack method implementations and utilities.
"""

__version__ = "0.1"
__author__ = "TentroLink"

# Only import what's currently implemented
from .methods import UDPFlooder
from .utilities import AttackModule, UI, Style

# Ensure cache directory exists
import os
cache_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'cache')
if not os.path.exists(cache_dir):
    try:
        os.makedirs(cache_dir)
    except:
        pass

__all__ = [
    'UDPFlooder',
    'AttackModule',
    'UI',
    'Style'
]
