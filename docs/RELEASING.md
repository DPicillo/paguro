# Releasing Paguro

For maintainers. A release is a tag; the workflow
`.github/workflows/release.yaml` does the rest.

## A release or a release candidate

1. `CHANGELOG.md` has a section `## vX.Y.Z – <date>` (a release candidate
   uses the section of the version it leads to, which may still say
   "unreleased").
2. `make ci` passes (the pre-push hook runs it anyway).
3. Tag and push the tag:

   ```
   git tag -a v0.1.0-rc.2 -m "Paguro v0.1.0-rc.2"
   git push github v0.1.0-rc.2
   ```

The workflow then:

| Step | Result |
|---|---|
| `make ci` | the same checks as every push |
| `make images-push installer-sources-push` | `ghcr.io/dpicillo/paguro/{paguro-controller,paguro-agent,paguro-node-installer,paguro-node-installer-sources}:<tag>` |
| `make image-scan` | fails on fixable vulnerabilities of severity high or above (reviewed exceptions: `.grype.yaml`) |
| `make sbom` | SPDX SBOMs of all four images |
| `make sign`, `make verify` | keyless signatures and SBOM attestations – **only if the repository is public** |
| chart metadata | the chart's default registry, Artifact Hub's image list with this tag, `artifacthub.io/prerelease` true for `-rc.N` |
| `make chart-push` | `oci://ghcr.io/dpicillo/charts/paguro`, version = tag without `v` (signed like the images) |
| `make artifacthub-push` | `artifacthub-repo.yml` as `ghcr.io/dpicillo/charts/paguro:artifacthub.io` ([below](#artifact-hub)) |
| `make plugin-dist` | `kubectl-paguro_<tag>_<os>_<arch>.tar.gz` for Linux and macOS (amd64, arm64) and Windows (amd64), and `kubectl-paguro_<tag>_checksums.txt` |
| GitHub release | notes from the changelog, SBOMs, the chart, the plugin; a release candidate is marked as pre-release |

A failed run: fix, then tag the next release candidate. Do not move a
tag that the workflow has already pushed images for – nodes pull with
`IfNotPresent` and keep what they cached under a tag.

## Artifact Hub

Artifact Hub lists the chart from its OCI repository
`oci://ghcr.io/dpicillo/charts/paguro`. The package page is made of the
chart itself: `Chart.yaml` (description, icon, keywords and the
`artifacthub.io/*` annotations – links, screenshots, images, the CRD and
its example, recommendations, the changes of the version), the chart's
`README.md` (the page's main text, so its images and links are absolute
URLs), `values.yaml` (tab "Default values") and `values.schema.json` (tab
"Values schema"). Check it before a release with Artifact Hub's
[CLI](https://artifacthub.io/docs/topics/cli/):
`ah lint --kind helm --path deploy/helm`.

`make artifacthub-push` pushes `artifacthub-repo.yml` as the tag
`artifacthub.io` next to the chart, with the media types Artifact Hub
reads for OCI repositories
(`application/vnd.cncf.artifacthub.config.v1+yaml`,
`application/vnd.cncf.artifacthub.repository-metadata.layer.v1.yaml`;
[Artifact Hub's documentation](https://artifacthub.io/docs/topics/repositories/helm-charts/#oci-support)).
The file holds the repository ID that Artifact Hub assigned; finding it
there proves that the publisher controls the registry, and Artifact Hub
marks the repository and its packages "Verified publisher". The release
workflow runs the target with **every release, release candidates
included**, after `make chart-push`; the content is the same each time,
only the tag moves. It skips the push while the file holds the all-zero
placeholder ID. By hand (after `oras login ghcr.io`):
`make artifacthub-push CHART_REGISTRY=oci://ghcr.io/dpicillo/charts`.

What to expect:

- Artifact Hub shows "Verified publisher" only once the package
  `charts/paguro` is public (it cannot read a private one) and the
  repository is enabled in Artifact Hub's control panel.
- The tracker processes repositories about every 30 minutes. It processes
  an OCI repository again only when its list of chart versions changed,
  so a changed `artifacthub-repo.yml` takes effect with the next chart
  version – one reason to push it with every release.
- A chart version Artifact Hub has indexed is not indexed again (for OCI
  repositories it cannot be reindexed). A fix to the README or the
  annotations reaches the page with the next version.

## While the repository is private

Everything the workflow publishes stays private: packages that a private
repository's workflow pushes to ghcr.io are private, and so is the GitHub
release. Nothing is signed, because keyless signatures are recorded in
Sigstore's public transparency log and would name the repository.

Artifact Hub knows the repository as `paguro` (user DPicillo, kind Helm,
URL `oci://ghcr.io/dpicillo/charts/paguro`, ID in `artifacthub-repo.yml`),
**disabled**: it is not tracked, and no package page exists. The API key
for it is kept outside this repository.

## Going public with v0.1.0

Making the repository public, signing (the transparency log keeps every
entry) and Artifact Hub's index cannot be taken back. In this order:

1. **Release candidate, still private.** Tag `v0.1.0-rc.N` and test what
   the workflow published, as a user would get it:
   - `helm registry login ghcr.io`, then install
     `oci://ghcr.io/dpicillo/charts/paguro --version 0.1.0-rc.N` on a lab
     cluster and on EKS. While the packages are private the nodes need a
     pull secret (`global.imagePullSecrets`).
   - Run the end-to-end tests on real clusters against it (migrations in
     every network mode, game servers with players, drains, Karpenter).
   - Read the GitHub release: the notes are the changelog's `v0.1.0`
     section; the assets are four SBOMs, the chart, five plugin archives
     and their checksum file.
   - The krew manifest renders and installs from the release's archives
     (`gh release download v0.1.0-rc.N -p 'kubectl-paguro_*'`, then
     `hack/krew/render.sh v0.1.0-rc.N kubectl-paguro_v0.1.0-rc.N_checksums.txt
     > paguro.yaml` and `kubectl krew install --manifest=paguro.yaml
     --archive=kubectl-paguro_v0.1.0-rc.N_linux_amd64.tar.gz`).
2. **Final changes.** The changelog section gets its date
   (`## v0.1.0 – <date>`); `make ci` passes; the history holds nothing that
   must not be public (credentials, internal addresses, build output).
3. **Release candidates out of the way.** Their GitHub releases and
   package versions are unsigned and become visible with the repository:
   delete the releases (`gh release delete v0.1.0-rc.N`) and, under
   Packages, the `-rc.N` versions of the five packages – or keep them as
   marked pre-releases.
4. **Make the GitHub repository public** (Settings → General → Danger
   Zone). Then, in Settings:
   - Code security → **Private vulnerability reporting** on – SECURITY.md
     and the README send reports there.
   - General: description, website
     (`https://www.picillo.de/blog/kubernetes-pod-live-migration/`),
     topics (`kubernetes`, `live-migration`, `criu`, `ebpf`,
     `game-servers`, `karpenter`, `checkpoint-restore`, `zero-downtime`,
     `agones`, `eks`, `helm-chart`, `kubectl-plugin`); Issues on.
   - General → Social preview → Edit → Upload an image:
     `docs/images/social-preview.png` (1280×640) – what links to the
     repository show in chats and on social media.
   - Branches: protect `main` (required status check: the CI job `check`).
5. **Tag `v0.1.0`.** Now the workflow signs the images and the chart and
   verifies the signatures; the release is not marked as a pre-release,
   and `artifacthub.io/prerelease` is false.
6. **Make the five packages public** (GitHub → Packages → each package →
   Package settings → Change visibility): `paguro/paguro-controller`,
   `paguro/paguro-agent`, `paguro/paguro-node-installer`,
   `paguro/paguro-node-installer-sources` (the CRIU sources the GPL asks
   for) and `charts/paguro`.
7. **Check from a machine that is not logged in:**
   - `helm pull oci://ghcr.io/dpicillo/charts/paguro --version 0.1.0` and
     `helm template paguro oci://ghcr.io/dpicillo/charts/paguro --version 0.1.0`
     (the images must say `ghcr.io/dpicillo/paguro/…:v0.1.0`);
   - `make verify PAGURO_REGISTRY=ghcr.io/dpicillo/paguro TAG=v0.1.0`, and
     the chart's signature with the same `cosign verify` flags as in
     SECURITY.md, for `ghcr.io/dpicillo/charts/paguro:0.1.0`;
   - the plugin archive and `sha256sum -c --ignore-missing
     kubectl-paguro_v0.1.0_checksums.txt`;
   - the README on GitHub: logo, badges (CI, release), links;
   - the chart's icon and the images of its README and screenshots load
     without a login – Artifact Hub stores the icon when it indexes the
     version (one that fails to load stays missing for that version);
     the browser loads the others from `main`:
     `https://raw.githubusercontent.com/DPicillo/paguro/main/docs/images/paguro.png`,
     `…/how-it-works.png`, `…/paguro-place-move.gif`,
     `…/paguro-place-{before,freeze,after}.png`.
8. **Artifact Hub:** enable the repository (Control Panel → Repositories →
   paguro → Edit → uncheck "Disabled"). The tracker indexes it within
   about 30 minutes; the `artifacthub.io` tag that the `v0.1.0` release
   pushed makes it a verified publisher ([Artifact Hub](#artifact-hub)).
   On the package page check the README with its images, the icon, the
   screenshots, the links, the CRD and its example, the default values
   and the values schema, the images' security report and the "Signed"
   badge. The README's Artifact Hub badge works from then on.
9. **krew** (by hand; krew-index takes a new plugin only through a pull
   request):
   - `hack/krew/render.sh v0.1.0 > paguro.yaml` (checksums from the
     GitHub release);
   - `kubectl krew install --manifest=paguro.yaml` (downloads from the
     release), `kubectl paguro nodes`, `kubectl krew uninstall paguro`;
   - fork `kubernetes-sigs/krew-index`, add the file as
     `plugins/paguro.yaml`, open a pull request "Add paguro plugin"; its
     checks install the plugin on every platform, and a maintainer reviews
     the name and the description
     ([krew's guide](https://krew.sigs.k8s.io/docs/developer-guide/release/new-plugin/));
   - once merged: in README.md, docs/INSTALL.md and the chart's NOTES,
     `kubectl krew install paguro` no longer needs "once listed in the
     krew index". Later releases: the same file for a pull request that
     updates it, or krew-release-bot in the release workflow.
10. **The blog post** is online at
    `https://www.picillo.de/blog/kubernetes-pod-live-migration/` – the
    README, the chart's Artifact Hub links and the repository's website
    point there (`curl -sfI <url>` must not fail).
