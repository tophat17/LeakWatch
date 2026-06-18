# Publishing LeakWatch to Unraid Community Applications

This guide takes LeakWatch from this repo to a one-click install in the Unraid
**Apps** tab (Community Applications, "CA").

## 1. Put it on GitHub under your account

1. Create a public GitHub repo named **`leakwatch`**.
2. Find-and-replace **`YOUR_GITHUB_USER`** with your GitHub username everywhere
   in this project (notably `unraid/leakwatch.xml`, `docker-compose.yml`,
   `README.md`). Quick check afterwards:
   ```bash
   grep -rn "YOUR_GITHUB_USER" .
   ```
3. Commit and push to the `main` branch.

## 2. Publish the Docker image to GHCR (automated)

The included workflow `.github/workflows/docker-publish.yml` builds a multi-arch
image and pushes it to the GitHub Container Registry on every push to `main`
and on version tags.

1. Push to `main` — the **Actions** tab will build and publish
   `ghcr.io/YOUR_GITHUB_USER/leakwatch:latest`.
2. In your repo: **Packages → leakwatch → Package settings → Change visibility →
   Public**. (CA must be able to pull it without authentication.)
3. Tag a release to also publish a versioned image:
   ```bash
   git tag v3.3.0 && git push --tags
   ```

Confirm these URLs load in a browser:
- Image: `https://github.com/YOUR_GITHUB_USER/leakwatch/pkgs/container/leakwatch`
- Icon:  `https://raw.githubusercontent.com/YOUR_GITHUB_USER/leakwatch/main/icon.png`
- Template: `https://raw.githubusercontent.com/YOUR_GITHUB_USER/leakwatch/main/unraid/leakwatch.xml`

## 3. Create an Unraid support thread

Community Applications expects every app to have a **support topic**.

1. Post a new thread in the Unraid forums (the "Docker Containers" / "Community
   Applications" area) introducing LeakWatch (you can reuse the README text).
2. Put that thread's URL into the `<Support>` tag in `unraid/leakwatch.xml`
   (you can keep the GitHub issues link as the `<Project>` / second support
   option). Commit the change.

## 4. Test the template locally on Unraid first

Before submitting, confirm it installs cleanly:

1. Unraid → **Docker → Add Container**.
2. Paste the raw template URL (from step 2) into the **Template** field.
3. Apply, open the WebUI, confirm it scans. Fix anything, push, retest.

## 5. Submit to Community Applications

CA is moderated — your template repo gets added to its app feed by the CA
maintainer.

1. Make sure your repo is public and contains the template at
   `unraid/leakwatch.xml`, the `icon.png`, a working public image, and a
   `<Support>` URL.
2. Follow the current submission instructions in the official CA documentation
   / the "Community Applications" support thread on the Unraid forums and
   request that your template repository be added. (The exact mechanism is
   maintained by CA and can change, so always use their latest instructions.)
3. Once accepted, LeakWatch appears in the **Apps** tab when users search for it.

## Updating later

- Push changes to `main` → the workflow republishes `:latest`.
- Bump `APP_VERSION` in `app/main.py` (it shows in the UI footer and drives the
  FastAPI version), add a note under `<Changes>` in `unraid/leakwatch.xml`, and
  tag a new release.
