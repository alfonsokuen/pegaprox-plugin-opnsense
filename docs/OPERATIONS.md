# Publication and runtime operations

The canonical repository is `https://git.idkmanager.com/idkmanager/pegaprox-plugin-opnsense.git`. GitHub is a push mirror. Publish to Gitea; a direct GitHub push can be replaced by the next mirror sync.

This checkout has `gitea` for the canonical repository and `origin` for the GitHub mirror. The default push remote is `gitea`. Verify both branch SHAs after publishing. Use fast-forward updates and preserve work from other contributors.

```text
git fetch gitea
git merge-base --is-ancestor gitea/main HEAD
git push gitea HEAD:main
git ls-remote gitea refs/heads/main
git ls-remote origin refs/heads/main
```

Before changing plugin configuration, back up the current file privately and verify the intended API access using read-only requests. Keep credentials out of logs and this repository; the encrypted vault is authoritative. Confirm that each credential is actually registered on its node: replicated users may share an API key, and a historical node-specific key may no longer exist.

Preserve read-only production mode until the actual pair is qualified for writes. Version 1.15.1 adds real isolated-lab qualification of CRUD, packet delivery, manual filter association, cleanup and HA, including an established TCP connection through failover. See [lab results and limits](QA_LAB_20260917.md); the new Fable review remains pending because its account returned HTTP 429. The release does not automatically enable production writes.
