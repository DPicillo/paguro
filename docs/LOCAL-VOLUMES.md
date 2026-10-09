# Node-local volumes

Status: **design, not implemented.** Today an `emptyDir` moves with its
content; `hostPath` volumes, local PersistentVolumes and other PVs bound to
one node are refused by the preflight ("data stays on the node"). This
document records what the copy path delivers, what a cloud node allows,
and how path-based local PVs can be supported.

## What Paguro's copy path delivers

An `emptyDir` is copied the way a local volume would be: the content
travels during pre-copy (`emptyDir base`), the freeze carries only the
files changed since. Measured with a test workload – random,
incompressible files plus a journal the writer fsyncs every 100 ms – from
k8s-w-4 to k8s-w-1 (4-vCPU VMs on different hosts, lab with a direct 10G
link between the hosts, ~6 Gbit/s):

| Data | Copied during pre-copy | Rate | Freeze | Migration |
|---|---|---|---|---|
| 2 GiB | 8.2 s | 262 MB/s | 1.54 s | 10.2 s |
| 5 GiB | 32.5 s | 165 MB/s | 1.28 s | 34.5 s |
| 10 GiB | 47.5 s | 226 MB/s | 3.46 s | 51.5 s |
| 10 GiB (back) | 73.9 s | 145 MB/s | 1.58 s | 76.9 s |
| 10 GiB (again) | 41.8 s | 257 MB/s | 1.43 s | 43.8 s |

After every run: the same process (boot id), the journal contiguous from
the first line to the last fsynced one, every file's SHA-256 unchanged.
The freeze does not grow with the data: what is copied before it is not
copied in it. One of the three 10 GiB runs froze for 3.5 s – its final
transfer took 2.35 s instead of 0.3–0.5 s; two repetitions with the
target's dirty pages logged (at most 0.9 GB dirty, 0.2 GB at the freeze)
did not reproduce it, so the cause is open. The rate is bounded by the VMs' disks and CPUs (reading
cold: 344–430 MiB/s; the stream is compressed and encrypted), not by the
link.

## What a cloud node allows

On AWS the instance, not Paguro, sets the rate. Baselines (sustained; the
"up to" values are bursts that depend on credits):

| Instance | Network baseline | EBS baseline (burst) | Rate to plan with |
|---|---|---|---|
| m6i/m7i.large | 0.78 Gbit/s (98 MB/s) | 81 MB/s (1,250 MB/s, ≥ 30 min per 24 h) | 81 MB/s |
| m6i/m7i.xlarge | 1.56 Gbit/s (195 MB/s) | 156 MB/s | 131–156 MB/s |
| m6i/m7i.2xlarge | 3.1 Gbit/s (390 MB/s) | 312 MB/s | 131–312 MB/s |
| m6i/m7i.4xlarge | 6.25 Gbit/s (780 MB/s) | 625 MB/s | 131–625 MB/s |

A gp3 volume delivers 125 MiB/s (131 MB/s) unless more throughput is
provisioned (up to 2,000 MiB/s), so a local-path volume on the default
root disk is capped there whatever the instance. Instance-store NVMe has
no EBS limit; there the network decides.

## The spot budget

EC2 gives a Spot Instance two minutes' notice; the rebalance
recommendation often comes earlier but is not guaranteed to. What has to
fit into the two minutes: noticing the signal (the metadata is polled
every 5 s), a target with room, the copy of everything leaving the node,
the freezes and restores, and a margin. That leaves about 60 s of copying,
and all pods moving off the node share it – memory (pre-copy round 1
copies the whole RSS) and local data together.

| Sustained rate | Fits into 60 s |
|---|---|
| 81 MB/s (large, EBS baseline) | 4.9 GB |
| 131 MB/s (gp3 default) | 7.9 GB |
| 195 MB/s (xlarge network baseline) | 11.7 GB |
| 260 MB/s (best lab run) | 15.6 GB |

So: for a spot evacuation, **about 5 GB per node** (memory plus local
data) is safe on small instances with a default gp3 root disk, 8–12 GB on
xlarge and larger instances or instance store. Beyond that the copy may
still be running when the instance goes. A spot evacuation therefore
needs a deadline, not a size: it estimates each pod's time from its RSS,
its local data and the rate measured on the node, migrates what fits in
priority order, and lets the rest be evicted as without Paguro. Planned
migrations (rebalancing, maintenance, upgrades) have no deadline; for
them local volumes are limited only by a configurable maximum and the
pre-copy time limit (10 GiB took 51–77 s in the lab).

Without migration, instance-store data is lost with a spot instance – a
local volume on instance store is exactly the data a migration saves.

## Write patterns

The copy is file-level: the base during pre-copy, then the files changed
since. That suits many files and appends – game worlds, logs, caches,
media, queues with segment files. It does not suit large files rewritten
in place (database data files, disk images): each change sends the whole
file again. v1 should add delta rounds (as for memory) and refuse – or
warn – when the changed files will not fit the freeze budget; block-level
deltas are out of scope.

## Design: path-based local PVs

Scope of a first version: PVs whose source is a `hostPath` or `local`
path with node affinity – local-path-provisioner (the default of k3s),
OpenEBS LocalPV Hostpath, static local PVs (also on instance store).
Node-local CSI drivers (TopoLVM, OpenEBS LVM/ZFS) need a mount on the
target and come later. `hostPath` volumes in a pod spec stay refused:
whether the pod owns the directory alone, Paguro cannot know.

1. **Preflight.** The pod opts in (annotation per volume) or its
   StorageClass is on an allowlist; the volume's used bytes (reported by
   the source agent) are within the limit.
2. **During pre-copy.** The controller creates a staging PVC
   (`<claim>-paguro-<id>`, same class and size) with the annotation
   `volume.kubernetes.io/selected-node: <target>`: the provisioner
   creates the PV on the target without a pod (tested with
   local-path-provisioner). The source agent sends the base, the target
   agent writes it into the new PV's path.
3. **Freeze.** The changed files, as for an `emptyDir`.
4. **After the commit**, the claim moves to the new PV under its own
   name: the new PV's reclaim policy set to Retain, the staging PVC
   deleted, the original PVC deleted (it goes once the source pod is
   gone), the new PV's claimRef cleared, the PVC created again under its
   name with `volumeName` set, the reclaim policy restored. Done by hand
   with local-path-provisioner: 0.94 s, and the provisioner later cleans
   up both the old and the new PV correctly.
5. **The replacement** is created after the swap: a pending pod that uses
   the claim would keep it from being deleted.

Before the commit an abort deletes the staging PVC and its PV; the source
is untouched. After the commit there is no way back, and the old PV goes
with its reclaim policy – as for any other volume.
