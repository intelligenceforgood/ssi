"""Evidence packaging and export for SSI investigations.

Includes STIX 2.1 IOC export and prosecution-ready evidence bundling.
"""

from ssi.evidence.stix import investigation_to_stix_bundle

__all__ = ["investigation_to_stix_bundle"]
