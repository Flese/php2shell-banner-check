# Publishing PHP2Shell Banner Check on GitHub

The project is prepared locally. No repository has been created or published in your account. This guide uses the proposed name `php2shell-banner-check`.

## 1. Prepare the files

1. Download and extract `php2shell-banner-check.zip`.
2. Open the `php2shell-banner-check` directory.
3. Check the project structure:

```text
php2shell-banner-check/
  README.md
  PUBLISHING.md
  php2shell_scanner.py
  test_php2shell_scanner.py
  targets.example.txt
  .gitignore
  .github/
    workflows/
      tests.yml
```

4. Do not add real inventories, CSV findings, credentials, or client data. The example target file contains only commented examples.
5. Open a terminal in the project directory and run:

```bash
python3 --version
python3 -m unittest -v test_php2shell_scanner.py
python3 php2shell_scanner.py --help
```

On Windows, you can use `py -3` instead of `python3`.

## 2. Create the repository

1. Sign in to GitHub.
2. Select `+` in the top navigation, then `New repository`.
3. Choose your personal account for a personal project. Do not use an organization without its authorization.
4. Enter `php2shell-banner-check` as the name.
5. Suggested description: `Low-impact PHP banner checks for PHP2Shell. Authorized security assessments only. No exploitation.`
6. Select `Public` if you want anyone to access it. Published files and their Git history will be visible.
7. Do not initialize with a README, `.gitignore`, or license. The first two are already included; no license has been selected.
8. Select `Create repository`.

Publishing a repository and choosing a reuse license are separate decisions. No LICENSE file is included, and no open-source license is claimed. Route all legal questions, especially licensing, ownership, employment agreements, and client contracts, through the legal team before publication. Do not attribute the project to Coalfire or use its branding without authorization.

## 3. Upload with Git

Install Git if necessary. From the project directory:

```bash
git init
git branch -M main
git add README.md PUBLISHING.md php2shell_scanner.py test_php2shell_scanner.py targets.example.txt .gitignore .github/workflows/tests.yml
git status
git diff --cached
```

Review every staged file. Then commit:

```bash
git commit -m "Add authorized PHP2Shell banner checker and documentation"
```

If Git requests your identity, configure your name and commit email. To avoid publishing your personal email, use the exact private commit address GitHub displays in your account settings. Do not invent a `noreply` address.

Copy the HTTPS repository URL shown by GitHub. Replace the placeholder below with that URL; do not type the placeholder literally:

```bash
git remote add origin <HTTPS_REPOSITORY_URL_COPIED_FROM_GITHUB>
git push -u origin main
```

Complete authentication using your Git credential manager or another supported GitHub method. Never embed passwords or tokens in source files, remote URLs, or commands you share.

## Browser upload alternative

If you do not want to use Git:

1. Open the empty repository and choose the existing-file upload link, or `Add file` > `Upload files` if shown.
2. Upload the extracted files, not just the ZIP. Put `README.md` and the Python files at the repository root, not inside another project folder.
3. Select `Commit changes`.
4. Verify `.gitignore` and `.github/workflows/tests.yml` were included. Some file browsers hide dotfiles.
5. If necessary, use `Add file` > `Create new file` to create the missing paths and copy their contents from the package.

## 4. Verify publication

1. Confirm the README appears on the repository home page.
2. Check that authorized-use restrictions and the one-request-per-protocol behavior are clearly documented.
3. Open `Actions` and inspect the `Unit tests` workflow. Wait for all configured Python versions to finish and review the results. If Actions is disabled, check your account or organization policy.
4. Do not present simulated examples as findings from real assessments.
5. Open the repository while signed out to verify public access, if you selected a public repository.

Preparation tests were local. No GitHub Actions run or real-server scan has been performed on your behalf.

## 5. Share responsibly

1. Copy the repository home-page URL. Share that address rather than a local file path.
2. Describe the project as a banner checker, not an exploit or definitive vulnerability detector.
3. State that it is only for owned systems or systems with explicit assessment permission.
4. Explain that `UNKNOWN` does not mean safe, and that runtime versions and vendor backports need internal verification.
5. Share only synthetic examples, never real client inventories or findings.

Recipients can select `Code` > `Download ZIP`, extract the project, and follow the README. Git users can clone the repository.

## 6. Maintain the project

When changing rules or code, update the tests and the rules-review date where appropriate:

```bash
python3 -m unittest -v test_php2shell_scanner.py
git add README.md PUBLISHING.md php2shell_scanner.py test_php2shell_scanner.py
git diff --cached
git commit -m "Update banner assessment rules and tests"
git push
```

Review staged changes before every publication. Do not add exploitation tests or silently change the single-request-per-protocol policy.
