# Contributing to Paguro

Thank you for considering a contribution. Paguro moves running workloads
between machines; a bug can freeze or lose someone's process. Correctness
comes before speed, and every change is measured on real clusters before it
is merged.

## Before you start

- **Bugs:** open an issue with the Migration's `status` (`kubectl get
  migration <name> -o yaml`), the controller's and both agents' logs, the
  Kubernetes, containerd, kernel and CNI versions.
- **Security problems:** never in a public issue – see [SECURITY.md](SECURITY.md).
- **Larger changes:** open an issue first and describe the problem and the
  measurement that shows it; the design is easier to agree on before the code.

## Development

```sh
make tools          # controller-gen
hack/install-hooks.sh   # runs `make ci` before every push
make ci             # gofmt, SPDX headers, go vet, unit tests, generated files, helm lint
make vulncheck      # govulncheck with reviewed exceptions
```

- Go code, comments, documentation, logs and messages are in English.
- Every source file starts with the SPDX header:

  ```
  // SPDX-License-Identifier: AGPL-3.0-only
  // Copyright (C) 2026 David Picillo
  ```

  (`hack/boilerplate.go.txt`; `make ci` checks it.)
- Comments explain *why* – usually with the measurement that led to the
  code ("measured: …"). Keep that style: the next person needs the reason.
- API changes: edit `api/v1alpha1`, run `make generate`, commit the
  regenerated CRD (`make ci` fails on stale generated files).
- Chart values: describe a new value in `values.yaml` (a comment) and in
  `values.schema.json` (its `description`), then run `make chart-docs` –
  it regenerates the values tables of the chart's README, which Artifact
  Hub shows as the package page (`make ci` fails on a value without a
  description).
- New dependencies: `go run ./hack/thirdparty` must pass (only licenses
  compatible with the AGPL-3.0).
- Tests: unit tests for logic, a lab measurement for behaviour on a real
  cluster (`docs/ROADMAP.md` lists the criteria). Say in the pull request
  what you measured and how.

## Developer Certificate of Origin

Contributions are accepted under the project's license,
AGPL-3.0-only, and you keep the copyright of your contribution. Every
commit must be signed off: its message ends with a line

```
Signed-off-by: Your Name <your.address@example.com>
```

which `git commit -s` adds from `user.name` and `user.email` (a GitHub
no-reply address is fine). With it you certify the
[Developer Certificate of Origin 1.1](https://developercertificate.org)
for that commit – that you wrote it or otherwise have the right to submit
it under the project's license:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

The CI checks every commit of a pull request for a sign-off by its author
(`hack/check-dco.sh`; locally: `hack/check-dco.sh origin/main HEAD`).
Forgot it? `git rebase --signoff origin/main` and push again.

## Code of conduct

Be kind and precise. Criticise code and measurements, not people. The
full text and how to report a problem: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
