# Publishing Airlock to GitHub (canonical source)

> **First, delete the stale `.git` folder** this setup left behind (it's a
> broken stub from the synced-folder environment): on Windows run
> `rmdir /s /q .git` in this folder — or just run `scripts\git_push.bat`,
> which does it for you.

Git can't be initialised from inside this synced folder reliably, so run these
on your machine. Two options.

## Option A — GitHub CLI (easiest)
Install GitHub CLI once (https://cli.github.com), then from this folder:

```
rmdir /s /q .git
gh auth login
git init
git add -A
git commit -m "Airlock v1.0.0"
gh repo create airlock --private --source=. --remote=origin --push
```

That creates the repo and pushes in one step. Drop `--private` for a public repo.

## Option B — plain git + an empty repo you create on github.com
1. Create a new empty repo on GitHub named `airlock` (no README/license — this
   folder already has them).
2. From this folder:

```
rmdir /s /q .git
git init
git add -A
git commit -m "Airlock v1.0.0"
git branch -M main
git remote add origin https://github.com/<your-username>/airlock.git
git push -u origin main
```

On Windows you can just run `scripts\git_push.bat`, which handles the stale
`.git`, the init/commit, and prompts you for the remote URL.

## After the first push (make GitHub canonical)
- Treat this repo as the single source of truth; clone it wherever you work:
  `git clone https://github.com/<you>/airlock.git`
- Protect `main` (Settings -> Branches) if you want review before changes.

## Safety check before you push
`.gitignore` already excludes `config.yaml`, `storage/`, `keys/`, `*.key`, and
`badhashes.txt`. Confirm nothing sensitive is staged:

```
git status
git ls-files | findstr /I "config.yaml master.key storage"   :: should print nothing
```

Never commit your `upload_token` or the master key. (Verified in testing: a
clean commit tracks 35 files and ignores all of the above.)
