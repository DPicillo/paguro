#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Tests the node installer against fake host roots (no real node needed).
#
#   build/node-installer/test-fakeroot.sh [image]      (make installer-test)
#
# For every scenario and containerd version it builds a host root in a temp
# dir (Alpine userland from the installer image + static upstream containerd
# + fake runc/systemctl), then runs the real installer image with
# PAGURO_HOST_EXEC=chroot and checks:
#   1. first run succeeds and installs what is missing
#   2. second run changes nothing (checksums of the whole fake root equal)
#   3. config.toml and the drop-in are valid TOML (python3 tomllib)
#   4. `containerd config dump` shows the handler, SystemdCgroup and
#      base_runtime_spec copied from the default handler, and the default
#      handler is unchanged
#   5. uninstall restores config.toml byte for byte
set -euo pipefail

IMAGE=${1:-paguro-node-installer:dev}
CTD_VERSIONS=${CTD_VERSIONS:-"2.0.7 2.1.5 2.4.1"}
HERE=$(cd "$(dirname "$0")" && pwd)
CACHE=${CACHE:-$HERE/../../bin/test-cache}
WORK=$(mktemp -d)
FAILS=0
trap 'docker run --rm -v "$WORK:/w" --entrypoint rm "$IMAGE" -rf /w/fake >/dev/null 2>&1; rm -rf "$WORK"' EXIT

mkdir -p "$CACHE"
for v in $CTD_VERSIONS; do
	[ -x "$CACHE/containerd-$v" ] && continue
	echo "fetching containerd $v (static)"
	curl -sfL "https://github.com/containerd/containerd/releases/download/v$v/containerd-static-$v-linux-amd64.tar.gz" |
		tar -xzO bin/containerd > "$CACHE/containerd-$v"
	chmod +x "$CACHE/containerd-$v"
done

pass() { echo "  PASS $*"; }
fail() { echo "  FAIL $*"; FAILS=$((FAILS + 1)); }

# --- sample configs ---------------------------------------------------------
# kubeadm-style v3 config, no imports (what `containerd config default` +
# SystemdCgroup edits typically look like)
cfg_kubeadm_v3() { cat <<'EOF'
version = 3
root = '/var/lib/containerd'
state = '/run/containerd'

[plugins.'io.containerd.cri.v1.images']
  snapshotter = 'overlayfs'

[plugins.'io.containerd.cri.v1.runtime']
  [plugins.'io.containerd.cri.v1.runtime'.containerd]
    default_runtime_name = 'runc'
    [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]
      runtime_type = 'io.containerd.runc.v2'
      [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]
        BinaryName = '/usr/sbin/runc'
        SystemdCgroup = true
EOF
}
# v3 config that already imports a drop-in dir (multi-line array, relative entry)
cfg_with_imports() { cat <<'EOF'
version = 3
imports = [
  "conf.d/*.toml",
]

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]
  runtime_type = 'io.containerd.runc.v2'
  [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]
    BinaryName = '/usr/sbin/runc'
    SystemdCgroup = false
EOF
}
# EKS AL2023, as rendered by nodeadm from config2.template.toml (containerd 2.x)
cfg_al2023() { cat <<'EOF'
version = 3
root = "/var/lib/containerd"
state = "/run/containerd"

[grpc]
address = "/run/containerd/containerd.sock"

[plugins.'io.containerd.cri.v1.images']
discard_unpacked_layers = true

[plugins.'io.containerd.cri.v1.images'.pinned_images]
sandbox = "localhost/kubernetes/pause"

[plugins."io.containerd.cri.v1.images".registry]
config_path = "/etc/containerd/certs.d:/etc/docker/certs.d"

[plugins.'io.containerd.cri.v1.runtime']
enable_cdi = true

[plugins.'io.containerd.cri.v1.runtime'.containerd]
default_runtime_name = "runc"

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]
runtime_type = "io.containerd.runc.v2"
base_runtime_spec = "/etc/containerd/base-runtime-spec.json"

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]
BinaryName = "/usr/sbin/runc"
SystemdCgroup = true

[plugins.'io.containerd.cri.v1.runtime'.cni]
bin_dir = "/opt/cni/bin"
conf_dir = "/etc/cni/net.d"
EOF
}
# EKS AL2023 with the legacy v2 template (NodeConfig passed v2 settings)
cfg_al2023_v2() { cat <<'EOF'
version = 2
root = "/var/lib/containerd"
state = "/run/containerd"

[grpc]
address = "/run/containerd/containerd.sock"

[plugins."io.containerd.grpc.v1.cri".containerd]
default_runtime_name = "runc"
discard_unpacked_layers = true

[plugins."io.containerd.grpc.v1.cri"]
sandbox_image = "localhost/kubernetes/pause"
enable_cdi = true

[plugins."io.containerd.grpc.v1.cri".registry]
config_path = "/etc/containerd/certs.d:/etc/docker/certs.d"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
runtime_type = "io.containerd.runc.v2"
base_runtime_spec = "/etc/containerd/base-runtime-spec.json"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
BinaryName = "/usr/sbin/runc"
SystemdCgroup = true
EOF
}
# Node provisioned by configuration management: schema 4, handler already in
# the main config
cfg_managed_v4() { cat <<'EOF'
# Managed by configuration management
version = 4
[plugins.'io.containerd.cri.v1.runtime']
  enable_criu = true
  [plugins.'io.containerd.cri.v1.runtime'.containerd]
    default_runtime_name = 'runc'
    [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]
      runtime_type = 'io.containerd.runc.v2'
      [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]
        BinaryName = '/usr/local/sbin/runc'
        SystemdCgroup = true
    [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.paguro]
      runtime_type = 'io.containerd.runc.v2'
      pod_annotations = ['paguro.dev/*']
      container_annotations = ['paguro.dev/*']
      [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.paguro.options]
        BinaryName = '/usr/local/bin/paguro-runc'
        SystemdCgroup = true
EOF
}

# scenario name | config generator ("" = no config.toml) | min containerd | expected drop-in | expect SystemdCgroup
SCENARIOS="
kubeadm-v3|cfg_kubeadm_v3|2.0|/etc/containerd/conf.d/paguro.toml|true
imports-v3|cfg_with_imports|2.0|/etc/containerd/conf.d/paguro.toml|false
al2023-v3|cfg_al2023|2.0|/etc/containerd/conf.d/paguro.toml|true
al2023-v2|cfg_al2023_v2|2.0|/etc/containerd/conf.d/paguro.toml|true
managed-v4|cfg_managed_v4|2.4|-|true
no-config||2.0|/etc/containerd/conf.d/paguro.toml|false
"

run_installer() { # mode ctd-version -> output in $WORK/out
	docker run --rm -v "$WORK/fake:/host" -v "$CACHE/containerd-$2:/host/usr/bin/containerd:ro" \
		-e PAGURO_HOST_EXEC=chroot -e PAGURO_SKIP_KERNEL_CHECKS=true -e PAGURO_SKIP_CRIU_CHECK=true \
		-e PAGURO_SKIP_LIVE_CHECK=true -e PAGURO_CONTAINERD_BIN=/usr/bin/containerd \
		-e PAGURO_RUNC_SRC=/host/stage/paguro-runc \
		"$IMAGE" "$1" > "$WORK/out" 2>&1
}
fake_sums() { # checksums of everything except volatile files
	docker run --rm -v "$WORK/fake:/f:ro" --entrypoint sh "$IMAGE" -c \
		'cd /f && find . -path ./run -prune -o -path ./proc -prune -o \( -type f -o -type l \) -print | sort | while read -r p; do if [ -L "$p" ]; then echo "L $(readlink "$p") $p"; else sha256sum "$p"; fi; done'
}
dump() { docker run --rm -v "$WORK/fake:/host" -v "$CACHE/containerd-$1:/host/usr/bin/containerd:ro" --entrypoint chroot "$IMAGE" /host /usr/bin/containerd config dump 2>/dev/null; }

for sc in $SCENARIOS; do
	IFS='|' read -r name gen minv dropin sysd <<< "$sc"
	for v in $CTD_VERSIONS; do
		printf '%s\n%s\n' "$minv" "$v" | sort -V -C || continue
		echo "== $name (containerd $v)"
		docker run --rm -v "$WORK:/w" --entrypoint rm "$IMAGE" -rf /w/fake
		mkdir -p "$WORK/fake"
		# Alpine userland as the "host", plus fake runc/systemctl
		docker run --rm -v "$WORK/fake:/f" --entrypoint sh "$IMAGE" -c '
			cp -a /bin /sbin /lib /usr /f/ && rm -f /f/usr/local/bin/paguro-node-installer
			mkdir -p /f/etc/containerd /f/stage /f/run /f/proc /f/tmp /f/usr/local/sbin /f/var/log
			cp /etc/passwd /etc/group /f/etc/
			printf "#!/bin/sh\necho \"runc version 1.3.0\"\n" > /f/usr/sbin/runc
			printf "#!/bin/sh\necho \"\$*\" >> /var/log/systemctl.log\n" > /f/usr/bin/systemctl
			printf "#!/bin/sh\n# fake paguro-runc\nexec /usr/sbin/runc \"\$@\"\n" > /f/stage/paguro-runc
			cp /f/usr/sbin/runc /f/usr/local/sbin/runc
			chmod +x /f/usr/sbin/runc /f/usr/local/sbin/runc /f/usr/bin/systemctl /f/stage/paguro-runc
			chmod 1777 /f/tmp'
		if [ -n "$gen" ]; then
			$gen > "$WORK/config.orig"
			docker run --rm -i -v "$WORK/fake:/f" --entrypoint sh "$IMAGE" -c 'cat > /f/etc/containerd/config.toml' < "$WORK/config.orig"
		fi
		dump "$v" > "$WORK/dump.before" || true

		# 1. first run
		if run_installer install "$v"; then pass "first run"; else fail "first run"; cat "$WORK/out"; continue; fi
		grep -E '^(bundle|criu |nft |crictl|runc.conf|paguro-runc|containerd-handler)' "$WORK/out" | sed 's/^/     /' || true
		fake_sums > "$WORK/sums1"

		# 2. idempotency
		if run_installer install "$v" && grep -q "nothing changed" "$WORK/out"; then pass "second run: nothing changed"; else fail "second run changed something"; cat "$WORK/out"; fi
		fake_sums > "$WORK/sums2"
		if diff -q "$WORK/sums1" "$WORK/sums2" >/dev/null; then pass "fake root identical after second run"; else fail "fake root differs"; diff "$WORK/sums1" "$WORK/sums2"; fi

		# 3. TOML validity
		for f in /etc/containerd/config.toml "$dropin"; do
			[ "$f" = - ] && continue
			[ -f "$WORK/fake$f" ] || { fail "$f missing"; continue; }
			if python3 -c 'import sys,tomllib; tomllib.load(open(sys.argv[1],"rb"))' "$WORK/fake$f"; then pass "valid TOML: $f"; else fail "invalid TOML: $f"; cat "$WORK/fake$f"; fi
		done

		# 4. effective config
		dump "$v" > "$WORK/dump.after"
		python3 - "$WORK/dump.before" "$WORK/dump.after" "$sysd" <<'EOF' && pass "dump: handler ok, default runtime unchanged" || fail "dump check"
import sys, tomllib
before = tomllib.load(open(sys.argv[1], "rb"))
after = tomllib.load(open(sys.argv[2], "rb"))
rts_a = after["plugins"]["io.containerd.cri.v1.runtime"]["containerd"]["runtimes"]
rts_b = before["plugins"]["io.containerd.cri.v1.runtime"]["containerd"]["runtimes"]
p = rts_a["paguro"]
assert p["runtime_type"] == "io.containerd.runc.v2", p
assert p["pod_annotations"] == ["paguro.dev/*"], p
assert p["container_annotations"] == ["paguro.dev/*"], p
assert p["options"]["BinaryName"] == "/usr/local/bin/paguro-runc", p
assert str(p["options"]["SystemdCgroup"]).lower() == sys.argv[3], p["options"]
assert p["base_runtime_spec"] == rts_b["runc"]["base_runtime_spec"], (p["base_runtime_spec"], rts_b["runc"]["base_runtime_spec"])
assert rts_a["runc"] == rts_b["runc"], "default runtime changed"
for k in ("io.containerd.cri.v1.images",):
    assert after["plugins"][k] == before["plugins"][k], k + " changed"
EOF
		[ "$dropin" != - ] && { echo "     drop-in:"; sed 's/^/       /' "$WORK/fake$dropin"; }
		[ -n "$gen" ] && { diff "$WORK/config.orig" "$WORK/fake/etc/containerd/config.toml" | sed 's/^/     config.toml diff: /' || true; }

		# 5. uninstall
		if run_installer uninstall "$v"; then pass "uninstall"; else fail "uninstall"; cat "$WORK/out"; fi
		if [ -n "$gen" ]; then
			if cmp -s "$WORK/config.orig" "$WORK/fake/etc/containerd/config.toml"; then pass "config.toml restored byte for byte"; else fail "config.toml not restored"; diff "$WORK/config.orig" "$WORK/fake/etc/containerd/config.toml"; fi
		fi
		dump "$v" > "$WORK/dump.uninst"
		if diff -q "$WORK/dump.before" "$WORK/dump.uninst" >/dev/null; then pass "effective config after uninstall == before install"; else fail "effective config differs after uninstall"; diff "$WORK/dump.before" "$WORK/dump.uninst" | head; fi
		if [ -e "$WORK/fake/opt/paguro" ] || [ -L "$WORK/fake/usr/local/sbin/criu" ]; then fail "leftovers after uninstall"; else pass "no leftovers (/opt/paguro, symlinks)"; fi
	done
done

# --- negative test: a foreign "paguro" handler with another binary --------
v=${CTD_VERSIONS##* }
echo "== conflict: foreign handler 'paguro' with wrong BinaryName (containerd $v)"
docker run --rm -v "$WORK:/w" --entrypoint rm "$IMAGE" -rf /w/fake
mkdir -p "$WORK/fake"
docker run --rm -v "$WORK/fake:/f" --entrypoint sh "$IMAGE" -c '
	cp -a /bin /sbin /lib /usr /f/ && mkdir -p /f/etc/containerd /f/run /f/tmp /f/stage
	printf "#!/bin/sh\necho \"runc version 1.3.0\"\n" > /f/usr/sbin/runc; chmod +x /f/usr/sbin/runc
	cp /f/usr/sbin/runc /f/stage/paguro-runc'
cfg_kubeadm_v3 > "$WORK/config.orig"
cat >> "$WORK/config.orig" <<'EOF2'
      [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.paguro]
        runtime_type = 'io.containerd.runc.v2'
        [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.paguro.options]
          BinaryName = '/usr/bin/something-else'
EOF2
docker run --rm -i -v "$WORK/fake:/f" --entrypoint sh "$IMAGE" -c 'cat > /f/etc/containerd/config.toml' < "$WORK/config.orig"
if run_installer install "$v"; then fail "installer accepted a conflicting handler"; else pass "installer refuses (exit != 0)"; fi
grep -E 'ERROR' "$WORK/out" | sed 's/^/     /'
cmp -s "$WORK/config.orig" "$WORK/fake/etc/containerd/config.toml" && [ ! -e "$WORK/fake/etc/containerd/conf.d/paguro.toml" ] &&
	pass "config untouched, no drop-in written" || fail "config modified despite conflict"

echo
if [ $FAILS -eq 0 ]; then echo "ALL TESTS PASSED"; else echo "$FAILS FAILURE(S)"; exit 1; fi
