---
name: git-push-auth
description: How to push this repo to GitHub — which account has write access
metadata:
  type: project
---

Repo `crb-chamalbandara/R26-CS-003` (HTTPS remote, Git Credential Manager `manager`).

Push access belongs to the **crb-chamalbandara** account. The machine's git identity is
`CRB-CyberSec-Dev` / `it22153272@my.sliit.lk`, which is NOT a collaborator — pushing as it
returns `403 Permission denied`.

**Why:** git user.name/email only label commit authorship; GCM's cached HTTPS token decides
push rights. GCM caches a github.com token beyond the plain Windows Credential Manager entry.

**How to apply:** if a push 403s as CRB-CyberSec-Dev, force a re-login:
`printf "protocol=https\nhost=github.com\n\n" | git credential reject` then `git push` —
GCM pops a browser login; sign in as crb-chamalbandara. See [[c2-component-owner]].
