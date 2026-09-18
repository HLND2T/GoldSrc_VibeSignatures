#!/usr/bin/env python3
"""Locate CGame_AppActivate using the shared session-local boundary recovery."""

from ida_preprocessor_scripts._cgame_appactivate_common import (
    ANCHOR_STRINGS,
    LOCATE_PY,
    preprocess_skill,
)
