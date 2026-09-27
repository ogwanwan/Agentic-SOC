"""Conservative, deterministic assertion matching; never executes log text.

This is a bounded Korean/English clause filter, not general language inference.
Unknown paraphrases still need catalog coverage or structured upstream evidence.
"""
from __future__ import annotations

import re
from typing import Iterable, Tuple

from .schema import TechniqueRule


# A dot inside shell.php, an IP, or a URL is not a sentence separator.
_CLAUSE_BREAK = re.compile(
    r"[\n;,!?。]+|\.(?=\s|$)|&&|\|\||"
    r"\s+\b(?:but|however|whereas|yet)\b\s*|(?<=으나)\s*|(?<=지만)\s*|(?<=없고)\s*",
    re.IGNORECASE,
)
_UNASSERTED = re.compile(
    r"\b(?:no|never|without|unconfirmed|unknown|unclear)\b|\bnot\b(?!\s+only\b)|"
    r"\b(?:wasn['’]t|isn['’]t|weren['’]t|didn['’]t|doesn['’]t)\b|"
    r"미확인|미관찰|미발견|미수행|미실행|불확실|확인\s*필요|"
    r"(?:확인|관찰|발견|실행|생성|전송)되지|"
    r"없(?:음|다|었|는|어|으|고)|않(?:음|았|는|다)|아님|아니었",
    re.IGNORECASE,
)
_HELP = re.compile(r"(?<![\w-])(?:--help|-h|--version)(?![\w-])")


def _clauses(text: str) -> Iterable[str]:
    return (part.strip() for part in _CLAUSE_BREAK.split(text) if part.strip())


def _natural_keywords(text: str, keywords: Tuple[str, ...]) -> set[str]:
    folded = text.casefold()
    return {word.strip().casefold() for word in keywords if word.strip() and word.strip().casefold() in folded}


def _command_keywords(text: str, keywords: Tuple[str, ...], *, include_help: bool = False) -> set[str]:
    matched = set()
    for keyword in keywords:
        word = " ".join(keyword.split())
        if not word:
            continue
        # ASCII boundary allows Korean particles (e.g. useradd를) but not
        # another executable/option (myuseradd, curl --upload-file-extra).
        pattern = r"(?<![\w.-])" + r"\s+".join(re.escape(part) for part in word.split()) + r"(?![A-Za-z0-9_-])"
        for occurrence in re.finditer(pattern, text):
            if include_help or not _HELP.search(text[occurrence.end():]):
                matched.add(word)
    return matched


def verdict_keywords(text: str, rule: TechniqueRule) -> Tuple[str, ...]:
    if not rule.allow_verdict_hits:
        return ()
    return tuple(sorted({word for clause in _clauses(text) if not _UNASSERTED.search(clause)
                         for word in _natural_keywords(clause, rule.attack_type_keywords)}))


def evidence_keywords(event_type: str, description: str, rule: TechniqueRule) -> Tuple[str, ...]:
    description_clauses = list(_clauses(description))
    # A later explicit retraction such as "C2 attribution unconfirmed" must
    # not be overruled by an earlier phrase "known C2 channel" in this evidence.
    if any(_UNASSERTED.search(clause) and _natural_keywords(clause, rule.context_subject_keywords)
           for clause in description_clauses):
        return ()

    def collect(clauses):
        accepted = set()
        rejected = False
        for clause in clauses:
            natural = _natural_keywords(clause, rule.evidence_keywords)
            commands = _command_keywords(clause, rule.evidence_command_keywords)
            mentioned = natural | _command_keywords(clause, rule.evidence_command_keywords, include_help=True)
            if _UNASSERTED.search(clause):
                rejected = rejected or bool(mentioned)
                continue
            rejected = rejected or bool(mentioned - natural - commands)
            if rule.required_context_keywords and not _natural_keywords(clause, rule.required_context_keywords):
                continue
            accepted.update(natural | commands)
        return accepted, rejected

    matched, rejected = collect(description_clauses)
    # An event label is not independent confirmation of an explicitly denied
    # action in its description. Other affirmative description clauses survive.
    if not rejected:
        from_type, _ = collect(_clauses(event_type))
        matched.update(from_type)
    return tuple(sorted(matched))
