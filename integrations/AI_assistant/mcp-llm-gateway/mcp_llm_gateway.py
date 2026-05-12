#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
mcp_llm_gateway.py (v3.7.0.1) — Modularized Gateway
===================================================

The main application logic has been migrated into the `mcp_gateway` package.
This file serves strictly as the application entry point.
"""

import sys
import os
import uvicorn

# We make sure the current directory is in the python path to allow imports.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp_gateway.main import app
from mcp_gateway.config import PORT

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, reload=False)