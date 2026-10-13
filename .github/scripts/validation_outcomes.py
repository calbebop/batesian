"""Validate per-rule scan outcomes used by fixture gates."""


STATUSES = {"findings", "no_findings", "skipped", "error"}


def rule_statuses(doc, rule_ids=None):
    expected = set(rule_ids) if rule_ids is not None else None
    outcomes = doc.get("rule_outcomes") if isinstance(doc, dict) else None
    if not isinstance(outcomes, list):
        raise ValueError("scan report is missing rule_outcomes")

    statuses = {}
    for item in outcomes:
        if not isinstance(item, dict):
            raise ValueError("scan report has a malformed rule outcome")
        rid, status = item.get("rule_id"), item.get("status")
        if not isinstance(rid, str) or not rid or \
                not isinstance(status, str) or status not in STATUSES:
            raise ValueError("scan report has a malformed rule outcome")
        if rid in statuses:
            raise ValueError(f"scan report has duplicate outcome for {rid}")
        statuses[rid] = status

    ruleset = doc.get("ruleset")
    if ruleset is not None:
        selected = ruleset.get("selected") if isinstance(ruleset, dict) else None
        if isinstance(selected, bool) or not isinstance(selected, int) or \
                selected != len(statuses):
            raise ValueError("scan report outcome count does not match selected rules")

    if expected is None:
        return statuses
    missing = expected - statuses.keys()
    if missing:
        raise ValueError(f"scan report is missing outcomes for {', '.join(sorted(missing))}")
    return {rid: statuses[rid] for rid in expected}


def incomplete_rules(doc, rule_ids):
    statuses = rule_statuses(doc, rule_ids)
    skipped = sorted(rid for rid, status in statuses.items() if status == "skipped")
    errors = sorted(rid for rid, status in statuses.items() if status == "error")
    return skipped, errors
