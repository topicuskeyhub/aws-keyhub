---
name: update-dependencies
description: Update the Go dependencies of aws-keyhub following the procedure in README.md. Runs `go get -u && go mod tidy` in a golang docker container, checks for unmaintained/archived dependencies, builds the binaries locally with build-release.sh and tests the basic commands and the browserCommand setting. Ends with a checklist for the PR, release and announcement.
allowed-tools: Bash(docker *) Bash(git *) Bash(gh *) Bash(grep *) Bash(cat *) Bash(go *) Bash(./build-release.sh) Bash(./build/*) Read AskUserQuestion
---

Follow the steps below to update the Go dependencies of aws-keyhub. Complete each step fully before moving on to the next.

---

## Step 0: Check the working tree

```
git status --short
```

If there are uncommitted changes, report them to the user and ask whether to continue or whether they should be stashed/committed first. Otherwise continue right away.

---

## Step 1: Update the dependencies in a golang container

Follow the procedure from `README.md` ("Update dependencies procedure"), but non-interactively so the output can be logged:

```
docker run --rm -v go-mod-cache:/go/pkg/mod -v "$(pwd)":/app -w /app golang:1.26 \
  bash -c "apt-get update -qq && apt-get install -y -qq zip && go get -u && go mod tidy"
```

Then check what changed:

```
git diff go.mod go.sum
```

If nothing changed (all dependencies were already up to date), tell the user and ask whether the skill should continue anyway (e.g. to still run the archived check and build/test) or stop here.

---

## Step 2: Check for unmaintained or archived dependencies

Collect the direct dependencies (the first `require (...)` block in `go.mod`, i.e. **without** the `// indirect` lines). For each dependency, determine the underlying GitHub repo (owner/repo, without submodule path or major version suffix such as `/v2`). For example, `github.com/aws/aws-sdk-go-v2/service/sts` belongs to repo `aws/aws-sdk-go-v2`.

For each unique GitHub repo, check whether it is archived and when it was last pushed to:

```
gh api repos/<owner>/<repo> --jq '{archived: .archived, pushed_at: .pushed_at, html_url: .html_url}'
```

- If a dependency is **archived**, or has not been pushed to for **more than ~1 year**: report it to the user with the repo name and last push date, and ask (via `AskUserQuestion`):
  > Dependency `<module>` appears to be unmaintained (archived: <yes/no>, last update: <date>). Do you want me to look for an alternative and replace it now, or skip this so a separate ticket can be created for it?
- If nothing stands out: briefly report that all direct dependencies are actively maintained and continue to step 3.

---

## Step 3: Build the binaries locally

`go` may not be on the PATH of this session. Fix that if needed:

```
PATH="/usr/local/go/bin:$PATH" ./build-release.sh
```

This builds all platform binaries (linux/windows/darwin, amd64/arm64) and creates the release zips in `release/`. If the script fails, show the error and stop — fix the problem before continuing.

---

## Step 4: Test the basic commands

Run the automatable smoke tests on the linux build:

```
./build/linux-amd64/aws-keyhub version
./build/linux-amd64/aws-keyhub help
./build/linux-amd64/aws-keyhub configure --help
./build/linux-amd64/aws-keyhub login --help
```

Verify that each command returns without a crash or unexpected error, and that `help` lists at least `login` as a subcommand.

`configure` requires an interactive prompt, and `login` / `login --role-arn` require a real KeyHub organization and browser flow, so you cannot fully test them. Tell the user:

> The automated checks (`version`, `help`, `--help` of `configure`/`login`) passed.
> Please test manually, with a real KeyHub configuration:
> - `aws-keyhub configure`
> - `aws-keyhub login`
> - `aws-keyhub login --role-arn <a valid role-arn>`
> - `aws-keyhub login` with a `browserCommand` in `~/.aws-keyhub/config-v2.json` (e.g. `["firefox", "-P", "<profile>", "{url}"]`, see README) — does the login link open in the chosen browser/profile?

---

## Step 5: Test the `browserCommand` setting

First run the Go unit tests (including `buildBrowserCommand` and detaching the browser process):

```
PATH="/usr/local/go/bin:$PATH" go test ./...
```

Then run the end-to-end test of the `browserCommand` setting against the linux build:

```
.claude/skills/update-dependencies/test-browser-command.sh ./build/linux-amd64/aws-keyhub
```

This script runs `aws-keyhub login` against a fake KeyHub (local python HTTP server) with a temporary `HOME`, so the real configuration is never touched. It verifies that:

- `{url}` as a separate argument is replaced, and arguments containing spaces stay a single argument
- without `{url}` the link is appended as the last argument
- `{url}` inside an argument (`--app={url}`) is replaced
- a non-existent command → warning + fallback to the default browser
- a command that exits with an error → warning + fallback to the default browser
- no / empty / blank `browserCommand` → default browser

Each scenario prints `PASS` or `FAIL` (with expected and actual output); the script exits with code 0 when everything passes. If anything fails: show the output to the user and stop.

---

## Step 6: Wrap up and next steps

Show a short summary of the updated dependencies (from the `git diff go.mod` of step 1: package, old version → new version), plus any findings from step 2.

Then give the user the following next steps verbatim:

> **Dependencies have been updated and built/tested locally.**
>
> Next steps (to do yourself):
> 1. Create a PR with the changes to `go.mod` / `go.sum`.
> 2. Create a new release (new tag) once the PR is merged.
> 3. Test the new release on Windows, macOS and Linux.
> 4. Announce the release in **#public-cloud**.
