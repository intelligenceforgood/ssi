"""Integration bridge between SSI and i4g core platform.

SSI writes investigation results directly to the shared database via
``ScanStore.create_case_record()``.  The legacy HTTP bridge was removed
in March 2026 — all persistence now uses direct SQL writes.
"""
