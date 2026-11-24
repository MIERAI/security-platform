# Security policy

Report vulnerabilities privately through GitHub's "Report a vulnerability" (Security tab), not in public issues.
You will get an answer within 7 days.

Design rules the product keeps (docs/design.md):
- collectors are read-only toward every target and never prompt for credentials;
- findings are attacker intelligence: they live only in the operator's private data directory, never in this
  repository, in metrics labels, dashboards or alert texts (aggregates only);
- secrets are read from 0600 files or environment variables and never logged.
