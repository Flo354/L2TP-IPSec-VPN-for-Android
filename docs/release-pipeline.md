# The release pipeline

How `.github/workflows/release-apk.yml` turns a push into a signed, downloadable APK, why it is
split the way it is, and the repository settings it cannot work safely without. Read this before
changing that file.

The short version: **the signing key never sits in a job that runs code from the repository.** Every
other rule below either supports that sentence or covers what it cannot.

## Contents

* [What it does](#what-it-does)
* [The CI signing key](#the-ci-signing-key)
* [Poisoned pipeline execution](#poisoned-pipeline-execution)
* [How the workflow is built against it](#how-the-workflow-is-built-against-it)
* [Repository settings it relies on](#repository-settings-it-relies-on)
* [What is not claimed](#what-is-not-claimed)
* [Rules for changing the workflow](#rules-for-changing-the-workflow)

## What it does

Every push to `master`, or a manual run from the Actions tab, goes through two jobs:

| Job | Runs | Holds | Token |
| --- | --- | --- | --- |
| `build` | the wrapper check, then Gradle: `:core:test`, `:app:testDebugUnitTest`, `:app:assembleRelease` with no signing config, so the APK comes out unsigned | no secret | `contents: read` |
| `sign` | the runner image's `zipalign` and `apksigner` on the APK from `build`, then `gh release create` | the signing key, from the `release` environment | `contents: write` |

The result is a GitHub release tagged `build-<run number>`, marked latest, with the APK attached as
`L2TP-IPSec-VPN.apk`, so the newest one is always at
<https://github.com/Flo354/L2TP-IPSec-VPN-for-Android/releases/latest/download/L2TP-IPSec-VPN.apk>.
The release notes give the commit and the signing certificate's SHA-256; compare it with
`apksigner verify --print-certs` on a download.

## The CI signing key

The pipeline signs with a key of its own, used nowhere else. The key for local builds — the one in
`keystore.properties`, see the [README](../README.md#a-signed-release-build) — never goes to GitHub.
If the CI key leaks, only the CI channel is compromised, and the reverse holds too.

The cost: Android refuses to update an app with an APK signed by a different key, so an APK from CI
and a local release build cannot be installed over each other. Pick one channel per device; switching
means uninstalling, which wipes the saved profiles and their credentials.

Generate it outside the repository:

```bash
keytool -genkeypair -v \
    -keystore ~/keystores/l2tpvpn-ci.jks \
    -storetype PKCS12 -alias l2tpvpn-ci \
    -keyalg RSA -keysize 4096 -validity 10000
```

and hand it over as three secrets of the `release` environment (see
[below](#repository-settings-it-relies-on) for creating it):

| Secret | Value |
| --- | --- |
| `RELEASE_KEYSTORE_BASE64` | `base64 -w0 ~/keystores/l2tpvpn-ci.jks`, piped to `wl-copy` or `xclip -selection clipboard` rather than printed into the terminal's scrollback |
| `RELEASE_KEYSTORE_PASSWORD` | the password given to `keytool`; with PKCS12 it is both the store and the key password |
| `RELEASE_KEY_ALIAS` | `l2tpvpn-ci` |

GitHub never shows a secret again, so the keystore file is the only copy you can recover: keep one
offline, somewhere you would trust with a password manager, then delete the working copy. Lose it
and no CI-installed app can ever be updated; leak it and anyone can sign an update that installs
cleanly over them.

## Poisoned pipeline execution

Poisoned pipeline execution (PPE, CICD-SEC-4 in the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/))
is getting a CI pipeline to run code of the attacker's choosing while it has access to something
worth stealing — here, the signing key, and with it the ability to ship an update every installed
copy will accept. It comes in three forms:

| Form | How | Example against this repository |
| --- | --- | --- |
| Direct | Edit the workflow file itself | a branch whose `release-apk.yml` adds `echo "$KEYSTORE_BASE64"`, or posts it somewhere |
| Indirect | Leave the workflow alone and edit what it runs | a line in `app/build.gradle.kts`, a unit test, `gradlew`, a swapped `gradle-wrapper.jar`, a Gradle plugin or a dependency that reads the environment or the disk |
| Public (3PE) | Either of the above, through a pull request from a fork | a "typo fix" PR that also touches a test |

Indirect PPE is the one that is easy to miss: any job that runs `./gradlew` runs code from the
repository, whatever the workflow file says, and so does any later step in the same job, because a
build step can leave something behind on the runner.

## How the workflow is built against it

| Measure | What it stops |
| --- | --- |
| **The key never shares a job with repository code.** `build` runs Gradle with no secret. `sign` holds the key and has no checkout; it runs only the runner image's `zipalign` and `apksigner` and the `gh` CLI, and treats the APK as data. Each job is a fresh VM | Indirect PPE. A poisoned build script, test, plugin or dependency runs where there is nothing to steal, and cannot leave anything behind for `sign` |
| **The key is an environment secret, and only `master` may deploy to `release`** | Direct PPE from a branch. A workflow edited on any other branch can name the environment; GitHub refuses it the secrets. Repository secrets would be readable by a workflow on any branch |
| **`sign` also checks `github.ref` itself** | A manual run on another branch, in case the environment's branch rule is ever loosened |
| **Only `push` and `workflow_dispatch` trigger it** | Public PPE. A fork's pull request never runs this workflow. `pull_request_target` and `workflow_run` are never used: both run with secrets for code nobody with write access has reviewed |
| **No `${{ }}` expression inside a `run:` script** | Script injection. Values the attacker can shape — a commit message, a branch or tag name — reach the shell as environment variables, never as shell code |
| **Every action pinned to a full commit SHA**, the version in a comment | A hijacked or moved tag. In March 2025 the tags of `tj-actions/changed-files` were repointed at a commit that dumped secrets into the logs of every workflow using it |
| **No cache** | Cache poisoning. Any job can write to the Actions cache through the runtime token, even one that never asks for caching, and the entry outlives its run; only a job that restores a cache is exposed, and `sign` restores none |
| **`gradle/actions/wrapper-validation`**, and `distributionSha256Sum` in `gradle-wrapper.properties` | A tampered `gradle-wrapper.jar` — a binary no diff review can read, and the first thing `./gradlew` runs — and a tampered Gradle distribution |
| **Least privilege**: `permissions: {}` at the top, `contents: read` for `build`, `contents: write` only for `sign`. `persist-credentials: false` on the checkout | A poisoned build pushing to the repository or tampering with releases using the job's own token |
| **The password stays off the command line**: `apksigner --ks-pass env:…`, and the keystore is written with `umask 077` and deleted on exit | Another process on the runner reading it from the process list |

## Repository settings it relies on

The workflow file cannot enforce any of these; without them, some of the measures above do nothing.

**Settings → Environments → New environment `release`**

* *Deployment branches and tags*: **Selected branches and tags**, with only `master`. This is what
  makes the key unreachable from any other branch.
* *Environment secrets*: the three secrets [above](#the-ci-signing-key). Make sure no **repository**
  secret of the same name exists; delete any.
* *Required reviewers*: yourself — **recommended**, with *Prevent self-review* left unchecked, or
  nobody could approve your own pushes. Every release then waits for an approval, so a stolen SSH
  key, or a token that can push but not approve deployments, still cannot publish a signed build on
  its own. A classic token with the `repo` scope can do both, which is one more reason not to keep
  one. The price is that releases are no longer fully automatic.
* *Allow administrators to bypass configured protection rules*: **unchecked**. When the only
  administrator is also the reviewer, the bypass adds a way around the approval and nothing else.

**Settings → Rules → Rulesets**, a ruleset targeting `master`

* *Restrict deletions* and *Block force pushes*.
* *Require a pull request before merging* if anyone else ever gets write access.

**Settings → Actions → General**

* *Actions permissions*: allow only actions created by GitHub plus `gradle/actions/wrapper-validation@*`,
  and turn on *Require actions to be pinned to a full-length commit SHA*.
* *Fork pull request workflows from outside collaborators*: *Require approval for all external
  contributors*.
* *Workflow permissions*: *Read repository contents and packages permissions*, and leave *Allow
  GitHub Actions to create and approve pull requests* unchecked.

**The account**: two-factor authentication, and no classic personal access token with the `repo` or
`workflow` scope lying around. Such a token can edit the workflow on `master`.

**Runners**: GitHub-hosted only. A self-hosted runner can keep state from one job to the next, which
undoes the split between `build` and `sign`.

## What is not claimed

* **Whoever can push to `master` owns the pipeline**, key included: they can rewrite this file. The
  perimeter is write access to `master` — the ruleset, the account's 2FA, its tokens and SSH keys.
  Once it is breached, required reviewers on the environment are the only control left, and they
  hold only if what was stolen cannot also approve deployments.
* **The key is protected, not the APK.** A poisoned build cannot reach the key, but it can make the
  APK malicious, and `sign` will sign it. What ends up in the APK is only as trustworthy as what is
  on `master`.
* **Dependencies are not verified** beyond what Gradle does by default: there is no
  `gradle/verification-metadata.xml`. A compromised library can change the APK, for the same reason
  as the point above. It still cannot reach the key.
* **GitHub itself is trusted**: the runner images, the secret store and the `actions/*` code at the
  pinned commits.

## Rules for changing the workflow

* Never add a checkout, a Gradle call or any script from the repository to `sign`. If signing ever
  needs more than the runner image's tools, it needs a third job, not a bigger `sign`.
* Never give `build` a secret, and never move a secret out of the `release` environment.
* Never add `pull_request_target`, `workflow_run` or a cache.
* Pin every new action to a full commit SHA, with its version in a comment, and read what it does
  before pinning it.
* Pass anything that comes from the event — commit message, branch name, PR title — through `env:`,
  never `${{ }}` inside `run:`.
