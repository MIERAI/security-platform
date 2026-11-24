"""Export ledger entries as OCSF 1.x Finding events (docs/design.md section 4). Consumers: SIEMs."""
SEV = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
CLASS = {"detection": (2004, "Detection Finding"), "vulnerability": (2002, "Vulnerability Finding"),
         "compliance": (2003, "Compliance Finding")}
STATUS = {"open": 1, "fixed": 4, "accepted": 3, "false_positive": 3}


def to_ocsf(e):
    uid, name = CLASS.get(e.get("kind", "detection"), CLASS["detection"])
    ev = {"class_uid": uid, "class_name": name, "category_uid": 2, "activity_id": 1,
          "severity_id": SEV[e["severity"]], "status_id": STATUS.get(e["status"], 99), "status": e["status"],
          "time": e["last_seen"],
          "metadata": {"version": "1.3.0", "product": {"name": "security-platform/" + e["collector"],
                                                        "version": e.get("collector_version", "")}},
          "finding_info": {"uid": e["id"], "title": e["title"], "first_seen_time": e["first_seen"],
                           "last_seen_time": e["last_seen"], "types": [e["check"]]},
          "resources": [{"type": e["asset"].split(":", 1)[0], "name": e["asset"].split(":", 1)[1]}],
          "remediation": {"desc": e["remediation"]}}
    if uid == 2003:
        ev["compliance"] = {"control": e["check"], "standards": [r for r in e.get("refs", []) if r.startswith(("cis:", "cis-"))]}
    if uid == 2002:
        a = e.get("attributes", {})
        ev["vulnerabilities"] = [{"cve": {"uid": a.get("cve"), "cvss": [{"base_score": a.get("cvss")}] if a.get("cvss") else [],
                                          "epss": {"score": a.get("epss")} if a.get("epss") is not None else None},
                                  "is_exploit_available": bool(a.get("kev")),
                                  "affected_packages": [{"name": a.get("package"), "version": a.get("installed"),
                                                         "fixed_in_version": a.get("fixed")}]}]
    return ev
