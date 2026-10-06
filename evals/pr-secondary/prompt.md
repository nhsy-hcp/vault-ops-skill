---
tags: [offline, pr]
max_turns: 14
allowed_tools: [Read, Glob, Grep, Skill]
---

I ran vault-ops health on our primary and health + audit on the performance replication secondary; the results are already saved. The secondary's audit shows fewer namespaces than the primary, and the primary's health mentions something called vault-pr-stale. Is our performance replication healthy, and can I trust an audit run on the secondary?
