"""ATT&CK TechniqueRule 전체 카탈로그."""

from .initial_access import RULES as INITIAL_ACCESS_RULES
from .post_exploitation import RULES as POST_EXPLOITATION_RULES


ALL_RULES = [
    *INITIAL_ACCESS_RULES,
    *POST_EXPLOITATION_RULES,
]


__all__ = [
    "ALL_RULES",
    "INITIAL_ACCESS_RULES",
    "POST_EXPLOITATION_RULES",
]