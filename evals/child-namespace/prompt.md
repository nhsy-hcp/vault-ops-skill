---
tags: [offline, namespace]
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---

I ran vault-ops audit and health with a token from our admin namespace (VAULT_NAMESPACE=admin). Licence, raft, audit devices and snapshots all came back empty. Is my token missing permissions? Should I add them to vault-ops-readonly, or enable an audit device?
