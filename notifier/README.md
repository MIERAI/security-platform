# Notifiers

Deliver the short daily summary (`sp digest`) to people: a chat, a phone, a speaker. Interface and adapters are in
`notifiers.py`; configuration in the instance (`notify:`), schedule as a runner job:

```yaml
notify:
  - {type: telegram, token_file: ~/.config/security-platform/telegram.token, chat_id_file: ~/.config/security-platform/telegram.chat}
runner:
  jobs:
    notify: {type: notify, schedule: "0 8 * * *"}     # every morning; `sp notify --dry-run` shows the text
```

Rules for every notifier: the text is aggregates only (it leaves the private boundary); secrets come from 0600 files;
errors never contain the secret; one failing notifier does not stop the others; notifications are not alerts (paging
stays with Prometheus/Alertmanager and the regression-only rules).
