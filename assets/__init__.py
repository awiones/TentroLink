"""
TentroLink Assets Package
------------------------
Contains attack method implementations and utilities.
"""

__version__ = "0.4"
__author__ = "TentroLink"

# Import all implemented attack methods
from .methods import (
    UDPFlooder,
    TCPFlooder,
    HTTPFlooder,
    TOR2WebFlooder,
    SYNFlooder
)
from .layer7 import OVHFlooder, CloudflareBypass
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
    'TCPFlooder',
    'HTTPFlooder',
    'TOR2WebFlooder',
    'SYNFlooder',
    'OVHFlooder',
    'CloudflareBypass',
    'AttackModule',
    'UI',
    'Style'
]
