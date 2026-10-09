# Operating Paguro

Install, upgrade and removal: [INSTALL.md](INSTALL.md). Security model:
[SECURITY.md](../SECURITY.md).

## Monitoring

### Metrics

Controller (`:8080/metrics`, Service `paguro-controller`):

| Metric | |
|---|---|
| `paguro_migrations_total{result}` | finished migrations: `Succeeded`, `Failed`, `RolledBack` |
| `paguro_migration_freeze_seconds` | histogram: how long the workload was frozen – what its clients notice |
| `paguro_migration_phase_seconds{phase}` | histogram: time per phase |
| `paguro_migration_wire_bytes` | histogram: bytes sent per migration |
| `paguro_migrations_active{phase}` | migrations not yet finished |
| `paguro_migration_oldest_active_seconds` | age of the oldest unfinished migration |
| `paguro_unmutated_pods` | pods labeled migratable that the webhook never saw (created while it was down) |

Agent (`:9556/metrics` on every node):

| Metric | |
|---|---|
| `paguro_agent_transfer_refused_total` | checkpoint data refused: wrong peer node, not for this node, unknown migration |
| `paguro_agent_transfer_cert_expiry_timestamp_seconds` | when the node's transfer certificate expires |
| `paguro_agent_route_repairs_total` | Cilium host routes of kept addresses restored (see [ARCHITECTURE.md](ARCHITECTURE.md)) |
| `paguro_agent_state_cleanups_total{kind}` | leftover checkpoints removed (`images`, `dump`, `directory`) |

With the Prometheus Operator the chart creates `PodMonitor`s for both
(`monitoring.podMonitor.enabled: auto`); without it the pods carry
`prometheus.io/scrape` annotations.

### Alerts

`monitoring.prometheusRule.enabled: auto` installs these rules
(`deploy/helm/paguro/files/alerts.yaml`); add the label your Prometheus
selects rules by (`monitoring.prometheusRule.labels`, e.g.
`release: kube-prometheus-stack`).

| Alert | Means | Do |
|---|---|---|
| `PaguroMigrationFailed` | a migration failed after its commit point: the workload was restored again from the checkpoint or cold-started | `kubectl paguro describe <migration>`; the message names the step and CRIU's error |
| `PaguroRollbacksFrequent` | many migrations rolled back (workloads kept running) | the abort reasons in the Migrations' status; often a target that is not ready (image pull, volume attach) |
| `PaguroFreezeSlow` | p90 freeze above 2 s | [Long freezes](#long-freezes) |
| `PaguroMigrationStuck` | a migration runs for over 30 min | its phase; `spec.timeoutSeconds` ends it |
| `PaguroUnmutatedPods` | migratable pods without Paguro's settings | restart them (events with reason `Unmutated` name them) |
| `PaguroControllerMetricsAbsent` | no controller metrics | the controller is down or not scraped |
| `PaguroTransferRefused` | a node sent checkpoint data it had no business sending | the agent's log (`transfer request refused`) names the peer; see SECURITY.md |
| `PaguroAgentCertificateExpiring` | an agent cannot renew its transfer certificate | is the controller running? `kubectl get csr \| grep paguro-agent` – a `Denied` request carries the reason |
| `PaguroAgentUnavailable` | agents not running (kube-state-metrics) | `kubectl -n paguro-system describe pod <agent>`; a node without agent takes part in no migration |

### Dashboard

`monitoring.grafanaDashboard.enabled: true` creates a ConfigMap
`paguro-dashboard` labeled `grafana_dashboard: "1"` for Grafana's dashboard
sidecar (set `monitoring.grafanaDashboard.namespace` if the sidecar watches
another namespace). The JSON is also at
`deploy/helm/paguro/files/dashboard.json` for manual import: migrations by
result, freeze percentiles, time per phase, bytes per migration, running
migrations, agent repairs and certificate validity.

## Long freezes

The freeze is the final dump, its transfer and the restore. What lengthens
it, and what helps:

| Cause | Visible as | Help |
|---|---|---|
| Memory written faster than the network copies it | many pre-copy rounds (`status.containers[].rounds`), `throttlePct` < 100 when auto-converge throttled the CPU | more bandwidth between nodes; `spec.preCopy.freezeBudgetMs` (target), `autoConverge` (default on); accept a longer `maxSeconds` |
| A busy source node | round 1 slow although the network is idle; the node's CPU saturated | the agent's CPU request (`agent.resources.requests.cpu`, 200m) is its weight against the workload – CRIU and the compression run in its cgroup. With 50m, GitLab's first round of 4.6 GiB on a saturated 2-vCPU node took 126–300 s (16–37 MiB/s). Raise it on busy nodes; auto-converge throttles the workload only after the third round |
| Large memory (first round copies all of it) | round 1 `sendMs` | 8 GiB over 1 GbE take ~70 s before the freeze – pre-copy runs while the workload runs, but the limit `spec.preCopy.maxSeconds` (default: four times the first round, at least 120 s) must allow the rounds after it |
| An RWO volume moves | `timings` shows the cutover; events `VolumeDetached`/`Attached` | a multi-attach volume type and `agent.preAttach.enabled` (attach during pre-copy) |
| A replacement under the same name (StatefulSet, Agones GameServer) | cutover mode `on-delete`/`same-name` | its sandbox is created inside the freeze (~1–1.5 s more than a Deployment) |
| A slow target node | `restoreMs` | the restore wrapper's log on the node, `/var/log/paguro/paguro-runc.log` |

After the freeze, a pod restored with lazy pages (from 64 MiB) gets its
memory from the target's copy of the checkpoint as it touches it. A
workload that touches all of it at once – a JVM walking its heap – runs at
the speed of that copy until it is in. It is fast while the checkpoint is
in the page cache, and the page cache of the received checkpoint is charged
to the agent's cgroup: a memory limit on the agent (`agent.resources`, none
by default) evicts it, and the restore reads from disk instead. Visible as
the `paguro-lazy-*` unit on the target running for seconds
(`journalctl -u 'paguro-lazy-*'`); measured with Minecraft (2 GB): 8.4 s
under a 1 GiB limit, 1.5–2 s without, the players' longest gap 7.6–7.8 s vs
1.1–1.3 s.

TCP peers notice more than the freeze: after a few seconds without answer
their retransmission timer backs off exponentially, so a 30 s freeze can
look like 50 s to them. UDP flows resume with the first packet.

## Everyday tasks

**Move everything off a node** (maintenance): `kubectl drain <node>`.
Paguro's eviction webhook turns the eviction of each migratable pod into
a migration (Migration `<pod>-evict-<uid>`, label
`paguro.dev/trigger: eviction`) and answers the eviction with 429, which
`kubectl drain` retries every 5 s as for a PodDisruptionBudget; once the
pod has moved, the drain goes on. Other pods are evicted as usual. The
same holds for every evicter: Karpenter (consolidation, expiry, spot
interruptions), the Cluster Autoscaler, managed node group upgrades.

- At most three migrations leave a node at a time
  (`controller.migrationsPerNode`); the others wait in phase `Pending`
  with a message, their pods running on. Pods frozen and restored together
  wait for each other's sandboxes on the target: eleven at once froze for
  up to 21 s each, one at a time for 0.7 s.
- If no node can take the pod yet, the migration waits for one in phase
  `Preflight` ("waiting until … for a target node"), at most
  `controller.evictionTargetWait` (2 min). Karpenter needs this: for a
  node it deletes, or one that got a spot interruption warning, it
  launches the replacement while it already drains, and the new node is
  ready after about 50 s on EC2. For drift, expiry and consolidation it
  launches first and drains once the replacement is up, so nothing waits.
- A node that goes at a known time – a spot instance two minutes after
  AWS's warning – carries `paguro.dev/terminates-at` (the agent reads EC2's
  instance metadata; anything else that knows the time may set the
  annotation). A migration that an eviction started then moves only if
  the time left covers an estimate of its duration (10 s plus the pod's
  memory request, or limit, at 96 MiB/s), and waits for a target only as
  long as that holds; otherwise the eviction goes through at once, and
  the pod restarts on another node sooner than a migration cut off by the
  instance's end would allow. Migrations started by hand only get a
  warning.
- A source agent that has not picked a migration up after 90 s will not:
  the migration rolls back (nothing was frozen), and its eviction goes
  through. A broken or missing agent holds a drain for that long, not
  for the migration's whole timeout.
- A migration that fails or rolls back lets the next eviction through:
  the pod is evicted as it would be without Paguro. The webhook fails
  open, so a Paguro outage never blocks a drain.
- A replacement that keeps the pod's name (StatefulSet, bare pod, Agones
  GameServer) is not taken for the evicted pod: the drain's retry for the
  pod that left is answered 404, and the drain moves on.
- `webhook.evictions: false` turns all of this off; `kubectl paguro
  drain <node>` migrates explicitly and reports each result.

**Rotate the agents' token:** delete Secret `paguro-agent-token` and
`helm upgrade` (it generates a new one); running migrations finish with
the old token, and the agents' rollout pairs no old agent with a new one
only if the release changes too – a migration started meanwhile between
an old and a new agent fails and rolls back.

**Agent certificates** renew themselves (every ~4.7 days). To force new
ones, restart the agents. To replace the CA, delete Secret
`paguro-agent-ca` and restart the controller, then the agents.

**Leftover data:** checkpoints hold a workload's whole memory. They are
deleted when a migration ends; the agents' state janitor removes anything
left behind (ten minutes after a migration ended, whole directories after
seven days). `paguro_agent_state_cleanups_total` counts what it found.

## Troubleshooting

See also [INSTALL.md, Troubleshooting](INSTALL.md#troubleshooting) for the
node installer.

| Symptom | Look at |
|---|---|
| Migration rejected in Preflight | `status.message` – every rejection names its reason (CPU features, volumes, host ports, missing agent, …) |
| Migration rolled back | `status.message` ("abort reason: …"), the source agent's log |
| Migration Failed after the commit | `kubectl paguro describe`; the replacement's events; `/var/lib/paguro/restore/<uid>/containers/<name>/restore-failed.log` on the target (`restore-failed-lazy.log`: a lazy restore that failed in the vDSO check or userfaultfd, after which the wrapper tried once more eagerly) |
| Restored pod does not get traffic | `kubectl get endpointslices -l kubernetes.io/service-name=<svc>`; with Cilium the agents' log lines "restored Cilium's host route" show route repairs |
| Two nodes never migrate to each other | `kubectl paguro version`: agents of different releases are not paired (during an upgrade's rollout, or a node left behind) |
| A node never becomes a target | node annotation `paguro.dev/agent-endpoint` empty: the agent has no transfer certificate yet (`kubectl get csr`), or its transfer server is not up |
| Agones GameServer went Unhealthy | was it held? `kubectl get gameserver <gs> -o yaml` (annotation `paguro.dev/migrating`), the Migration's events (`GameServerMoved`), [AGONES.md](AGONES.md) |
