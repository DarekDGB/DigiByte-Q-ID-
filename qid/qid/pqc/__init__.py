"""
qid/pqc package

Internal: algorithm-specific liboqs wiring helpers.

We use qid/pqc/ (not qid/crypto/) because this repo already has qid/crypto.py,
and Python cannot safely have both qid/crypto.py and qid/crypto/ package.
"""

from __future__ import annotations
