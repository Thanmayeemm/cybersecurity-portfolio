"""
Ensure API payloads are strict JSON–safe (no NaN/Infinity) and easy for clients to parse.
"""
from __future__ import annotations

import math
from decimal import Decimal
from typing import Any


def sanitize_for_json(obj: Any) -> Any:
    """
    Recursively replace NaN/Inf floats with None; normalize Decimals to float.
    Prevents invalid JSON like {"x": NaN} that breaks JavaScript JSON.parse.
    """
    if obj is None:
        return None
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, Decimal):
        return sanitize_for_json(float(obj))
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return None
        return obj
    if isinstance(obj, int) and not isinstance(obj, bool):
        return obj
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return {str(k): sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize_for_json(x) for x in obj]
    return str(obj)
