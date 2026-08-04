# SSH re-sign rewrite map (2026-08-04)

All commits on `release/v1.0.0` and `main` were rewritten to **SSH-sign** as
**AlphaOne \<Justin@alpha-one.mobi\>** (GitHub user **alphaonedev**).
GitHub bot PGP merge committers (`web-flow` / `noreply@github.com`) were normalized.

## Key cert tip remaps

| Role | Old SHA | New SHA |
|------|---------|---------|
| first cert-note tip / min cut ancestor | `b95ad9780585e6a7354f9ae994e0d95829913567` | `0130b2f191120b1eed49df7ab53403551cfa275c` |
| recommended cut tip (Gate1 empty + sal) | `52fcff95b2d27e7a9a297593e3a10b458f69435f` | `b1bd4c59a84cc864095ab459ee84134e0a621a85` |
| Gate3 measure binary (never cut alone) | `d742f3314860e199a75c257c554835dabddef1b0` | `c1c6055d66008f108a9eb2bfc23d2d4190e357fa` |
| pre-rewrite release tip (#2702) | `b4512b8430afac1c9d45cb73c195396bab4fdf08` | `c45e2b37630cd03be2f2ec7a80ebc9299441aca7` |
| pre-rewrite cert tip-align merge | `54ba094fa4d71ecd6427b77e03f6feb52a4f02ec` | `b44a2c9a4af50eeefe2b738f3b349f5f32645ab0` |
| claims train #2659 LAST | `f95d889e6800f5413152f3e4aa61f727d59d9cf2` | `8a52069a8da1844be126e0ac7d2d97948feaf5ce` |

**New release tip:** `c45e2b37630cd03be2f2ec7a80ebc9299441aca7`

## Policy going forward

- Commit with `gpg.format=ssh`, `user.signingkey` = AlphaOne ed25519 pub,
  `user.email=Justin@alpha-one.mobi` (maps to GitHub **alphaonedev**).
- Prefer **local** `git merge --no-ff -S` + push — never `gh pr merge`
  (GitHub web-flow PGP committer is not AlphaOne SSH).

Full map: 3174 commits (see operator scratch `/tmp/sha-map-release.json` if retained).
