# Cloud engine and import fixtures (contract tests)

Fictional identifiers only. No secret, no real account.

| file | what | origin |
|---|---|---|
| prowler-aws.ocsf.json | Prowler json-ocsf output | a real Prowler run against LocalStack (e2e/cloud-localstack), trimmed to the fields the collector reads |
| prowler-gcp.ocsf.json, prowler-azure.ocsf.json | Prowler json-ocsf output | hand-built in the OCSF 1.5 Detection Finding shape Prowler 5.x emits (check ids exist in Prowler 5.49) |
| scoutsuite-aws.json | ScoutSuite results object (the JSON inside scoutsuite_results_*.js) | iam/s3: a real ScoutSuite 5.14.0 run against LocalStack, trimmed; ec2: hand-built in the same shape |
| securityhub-asff.json | `aws securityhub get-findings` (ASFF) | hand-built per the ASFF schema |
| scc-findings.json | `gcloud scc findings list --format=json` | hand-built per the SCC Finding resource |
| defender-assessments.json | Azure Resource Graph export of microsoft.security/assessments | hand-built per the assessments resource |
