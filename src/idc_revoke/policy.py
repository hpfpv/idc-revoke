"""Edit the value list of one condition in one statement of a policy document.

Pure functions: no AWS calls. The deny policy they edit is documented at
https://docs.aws.amazon.com/singlesignon/latest/userguide/prereqs-revoking-user-permissions.html
"""

import copy
from typing import Any

PLACEHOLDER = "PLACEHOLDER-NOT-A-REAL-VALUE"

Document = dict[str, Any]


class StatementNotFoundError(LookupError):
    """The statement, or its condition operator and key, is not in the policy."""


def _locate(
    document: Document, sid: str, operator: str, key: str
) -> tuple[dict[str, Any], str]:
    """Return the condition block and the key as spelled in the policy."""
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if statement.get("Sid") != sid:
            continue
        block = statement.get("Condition", {}).get(operator, {})
        for existing in block:
            if existing.lower() == key.lower():
                return block, existing
    raise StatementNotFoundError(f"no {operator} on {key} in statement {sid!r}")


def _as_list(value: str | list[str]) -> list[str]:
    return [value] if isinstance(value, str) else list(value)


def list_values(document: Document, sid: str, operator: str, key: str) -> list[str]:
    """Return the values currently in the deny list."""
    block, existing = _locate(document, sid, operator, key)
    return _as_list(block[existing])


def add_value(
    document: Document, sid: str, operator: str, key: str, value: str
) -> Document:
    """Return a copy of the policy with the value added to the deny list."""
    result = copy.deepcopy(document)
    block, existing = _locate(result, sid, operator, key)
    values = _as_list(block[existing])
    if value not in values:
        values.append(value)
    block[existing] = values
    return result


def remove_value(
    document: Document,
    sid: str,
    operator: str,
    key: str,
    value: str,
    placeholder: str = PLACEHOLDER,
) -> Document:
    """Return a copy of the policy without the value.

    A condition cannot have an empty list, so a placeholder that matches
    nobody is left when the last value is removed.
    """
    result = copy.deepcopy(document)
    block, existing = _locate(result, sid, operator, key)
    values = [item for item in _as_list(block[existing]) if item != value]
    block[existing] = values or [placeholder]
    return result
