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

Preserve read-only production mode until an isolated lab has qualified writes, packet delivery, filter association, cleanup and HA propagation. The v1.15.0 release validates configuration round-trips using a simulator and performs live production reads only.
