"""Named boolean predicates usable inside YAML rule `condition` expressions.

Keep this the single place new predicates get registered so rule authors
have a discoverable, closed vocabulary instead of arbitrary code.
"""
from __future__ import annotations

from core.capabilities import name_implies_readonly, schema_has_write_params
from core.models import ToolDeclaration


def predicates_for(tool: ToolDeclaration) -> dict[str, bool]:
    return {
        "name_implies_readonly": name_implies_readonly(tool),
        "schema_has_write_params": schema_has_write_params(tool),
    }
