"""Check whether fixture rules completed without skips or errors."""


def incomplete_rules(doc, rule_ids):
    if "skipped" not in doc or "errors" not in doc:
        raise ValueError("scan report is missing rule outcomes")
    expected = set(rule_ids)
    skipped = sorted(expected & {item["rule_id"] for item in doc["skipped"]})
    errors = sorted(expected & {item["rule_id"] for item in doc["errors"]})
    return skipped, errors
