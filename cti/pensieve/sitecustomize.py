"""Monkey-patch aiohttp.ClientSession to honor HTTP_PROXY env vars.

The connector runs on a Docker-internal network with no direct internet
access. All egress goes through the worker's authenticated HTTP proxy
(injected via HTTP_PROXY/HTTPS_PROXY). aiohttp ignores proxy env vars
unless trust_env=True, so we patch the default.
"""
import aiohttp as _aio

_orig_init = _aio.ClientSession.__init__

def _patched_init(self, *a, **kw):
    kw.setdefault("trust_env", True)
    return _orig_init(self, *a, **kw)

_aio.ClientSession.__init__ = _patched_init
