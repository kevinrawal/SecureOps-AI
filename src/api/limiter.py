"""Shared slowapi Limiter singleton.

Imported by both ``main.py`` (to attach to ``app.state``) and route modules
(to use as a decorator source). Using the same instance is required by slowapi
to correlate per-route counters with the registered exception handler.
"""
from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter: Limiter = Limiter(key_func=get_remote_address)
