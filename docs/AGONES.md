# Agones game servers

Paguro moves Agones game servers – `GameServer`s from a `Fleet` or on their
own – with the game state in memory: players stay in the session, an
`Allocated` GameServer stays `Allocated`, and Agones learns the new node.

## Install

Install Agones first, then Paguro: the chart enables the integration when it
finds the `GameServer` API (`agones.enabled: auto`; set `true` to force it).
Kubernetes 1.30 or newer (admission policies). Mark the game server pods
migratable in the fleet's pod template:

```yaml
spec:
  template:            # GameServer
    spec:
      template:        # pod
        metadata:
          labels: {paguro.dev/migratable: "true"}
```

Migrate like any pod: `kubectl paguro migrate <gameserver> -n <ns>` (the pod
has the GameServer's name).

## What happens

Agones owns exactly one pod per GameServer, found by the GameServer's name,
and declares the GameServer `Unhealthy` – a Fleet then replaces it with a
fresh process – when that pod is deleted, missing, or appears on another
node. Paguro therefore:

1. checks the GameServer (`Ready`, `Reserved` or `Allocated`, not being
   deleted) and the guard policy;
2. copies the memory while the game runs (pre-copy), freezes, dumps;
3. marks the GameServer `paguro.dev/migrating`; the chart's admission
   policy `paguro-agones-guard` turns away Agones' updates to `Unhealthy`
   while the mark is there (Agones retries them);
4. deletes the source pod and creates the replacement under the same name,
   with the GameServer as owner, on the target node, where it is restored;
5. points the GameServer at the target node (`status.nodeName`, `address`,
   `addresses`, as Agones computes them) and removes the mark in one
   update – Agones' retries now find a healthy pod where the GameServer
   says it is.

A migration that ends before the replacement exists removes the mark, and
Agones judges the GameServer by its pod again.

## How players reach the server

The pod keeps its IP (Cilium, Calico), so everything that reaches the pod
through the cluster network keeps working:

| Players connect through | During a migration |
|---|---|
| a Service per GameServer (NodePort, LoadBalancer) or a proxy in front (e.g. Quilkin) | session kept, only the freeze |
| the pod IP (in-cluster clients) | session kept, only the freeze |
| **a host port** (`portPolicy: Dynamic`/`Static`, Agones' default) | the node's address changes – players connected to the old node lose the connection; Agones hands out the new address to new players |

Host ports are the node's address, not the pod's: after the move the pod
answers on the target node's address. Paguro keeps the host port number
(the target must have it free) and warns in the Migration's status. For
migratable game servers use `portPolicy: None` and a Service per
GameServer, or a UDP proxy that forwards to the pod IP.

Measured in the lab (Cilium 1.20, Agones 1.61, Allocated GameServer, 4
players and 5 joins/s per path):

| Exposure | Freeze | Players |
|---|---|---|
| `portPolicy: None` + NodePort Service, external clients through a third node; in-cluster through the ClusterIP and the pod IP | 1.98–2.10 s (two runs) | 0 session resets, 0 socket errors, all 250 joins on every path |
| host port (Agones default) | 2.08 s | pod IP path as above; host port path lost (connection refused at the old node) |

The freeze is longer than for Deployments (≈0.7 s): the replacement can
only be created once the source is gone (same name), so its sandbox is set
up inside the freeze.

## Agones' view during the move

Agones logs the refused updates, for example:

```
HealthController: error updating GameServer arena-x/games to unhealthy:
... ValidatingAdmissionPolicy 'paguro-agones-guard' ... denied request:
Paguro is moving GameServer arena-x to another node ...
```

That is expected; the GameServer's events show `GameServerMoved` on the
Migration and no `Unhealthy`.
