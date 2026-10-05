---
type: llm
---

The findings file has `coverage.complete: false`: Sentinel EGP and RGP policies in tn009/ were denied, and tn009/soc2/ was not collected at all (including its child namespaces). The response:
1. Says early (before the findings detail) that the results are partial or incomplete.
2. Names the denied scopes: Sentinel policies in tn009/ and the tn009/soc2/ subtree.
3. Attributes the gaps to the token's policy and points to the vault-ops read-only policy (vault-ops-readonly.hcl) as the fix.
4. Does not say tn009/soc2/ or Sentinel in tn009/ is clean or has no findings.
