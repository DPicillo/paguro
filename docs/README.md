# Paguro documentation

## Using Paguro

| Document | For |
|---|---|
| [INSTALL.md](INSTALL.md) | requirements, the Helm chart, the node installer, on-premises clusters, Amazon EKS (with Karpenter), uninstalling, troubleshooting the installation |
| [OPERATIONS.md](OPERATIONS.md) | metrics, alerts, dashboard, drains and autoscalers, long freezes, troubleshooting migrations |
| [CNI.md](CNI.md) | which CNI keeps the pod IP, which gets connection translation, what each was tested with |
| [AGONES.md](AGONES.md) | game servers managed by Agones |
| [../SECURITY.md](../SECURITY.md) | security model, hardening values, verifying releases, reporting vulnerabilities |
| [../CHANGELOG.md](../CHANGELOG.md) | what changed, measured results, known limitations |

## How it works (design notes)

| Document | About |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | components, the phases of a migration and the code behind each step |
| [PHANTOM-MODE.md](PHANTOM-MODE.md) | connection translation when the pod gets a new IP: model, datapath, what survives |
| [LOCAL-VOLUMES.md](LOCAL-VOLUMES.md) | node-local volumes: measurements, the spot budget and a design (not implemented) |

## The project

| Document | About |
|---|---|
| [ROADMAP.md](ROADMAP.md) | status and what comes next |
| [RELEASING.md](RELEASING.md) | releases and release candidates, the path to a public release |
| [THIRD-PARTY.md](THIRD-PARTY.md) | third-party components and licenses, the CRIU sources |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | building, testing, contributing |
| [../CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | how we treat each other, reporting problems |
