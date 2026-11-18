# Releasing JScope to GitHub and PyPI

This project supports two distribution paths:

- GitHub: source repository, tagged releases, and downloadable source archives.
- PyPI: installable Python package (`pip install jscope`).

## 1. Prepare a release

1. Run the full test suite: `pytest -q`.
2. Build and validate distributions:

   ```bash
   python -m pip install --upgrade build twine
   python -m build
   python -m twine check dist/*
   ```

3. Verify the package metadata and version in `jscope/__init__.py` and `pyproject.toml`.
4. Commit the changes and push the branch to GitHub.

## 2. Publish on GitHub

The intended canonical repository is `LIME1Star/Jscope`. Confirm `git remote -v` points to that repository before pushing:

```bash
git remote -v
git status
git add .
git commit -m "Release JScope <VERSION>"
git push origin main
git tag v<VERSION>
git push origin v<VERSION>
```

Then open the repository on GitHub, create a Release from tag `v<VERSION>`, add release notes, and publish it. Attach the built `dist/*.whl` and `dist/*.tar.gz` if you want users to download the package directly from GitHub as well. Do not commit `dist/` unless that is an intentional project policy.

## 3. Publish on PyPI manually (first release / fallback)

The `jscope` project already exists on PyPI. Open the existing project at https://pypi.org/project/jscope/ and confirm that your PyPI account has maintainer/owner access before publishing. Do not try to create a second project with the same name. Then configure a trusted publisher (recommended) or use an API token.

For token-based publishing, store the token securely and run:

```bash
python -m twine upload dist/*
```

Twine prompts for credentials if they are not supplied. Never put a PyPI token in source code, shell history, a committed file, or a GitHub workflow YAML.

## 4. Publish on PyPI automatically with GitHub Actions (recommended)

The included `.github/workflows/publish-pypi.yml` publishes when a GitHub Release is published using PyPI Trusted Publishing (OIDC); no long-lived PyPI token is stored in GitHub.

Before the first release:

1. On PyPI, open **Publishing** for the existing `jscope` project.
2. Add a GitHub Actions trusted publisher with owner `LIME1Star`, repository `Jscope`, workflow filename `publish-pypi.yml`, and environment name `pypi`.
3. In GitHub, create an environment named `pypi` if required by your repository settings.
4. Ensure the workflow has `id-token: write` permission (already set in the workflow).
5. Publish a GitHub Release. The workflow builds, validates, and uploads the wheel and source distribution.

The project name in `pyproject.toml` is `jscope`. The existing PyPI project must be under your account or an organization where you have publishing rights; if you do not control it, stop and resolve ownership before attempting publication.

## 5. Install after publication

```bash
python -m pip install --upgrade jscope
jscope
```

For a GitHub source install:

```bash
python -m pip install --upgrade "git+https://github.com/LIME1Star/Jscope.git"
```

## 6. Release checklist

- [ ] Tests pass on supported Python versions.
- [ ] `python -m build` succeeds.
- [ ] `twine check` succeeds.
- [ ] Version is incremented and tag matches it.
- [ ] GitHub release notes describe user-visible changes.
- [ ] PyPI trusted publisher points to the exact repository/workflow/environment.
- [ ] `pip install jscope` works in a clean virtual environment.
- [ ] `jscope` opens the wizard in an interactive terminal.
- [ ] `jscope --help` and existing direct commands still work.
