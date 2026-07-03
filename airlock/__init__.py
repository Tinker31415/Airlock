"""Airlock — a quarantined, malware-scanned, encrypted file drop for subprojects.

Devices upload through an authenticated web page (exposed via Cloudflare Tunnel);
files are quarantined, screened, and only cleared files are released — encrypted
per subproject — for background tasks to consume by name.

Subproject usage:

    from airlock import Airlock
    drop = Airlock("BLR - open data mining")
    for path in drop.pull_new(dest="./data"):
        process(path)
"""
from .client import Airlock

__version__ = "1.0.0"
__all__ = ["Airlock", "__version__"]
