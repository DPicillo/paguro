#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# paguro-node-installer – prepares a Kubernetes node for Paguro.
#
# Runs as the first initContainer of the paguro-agent DaemonSet (privileged,
# hostPID, host root filesystem mounted at $HOST_ROOT). It is idempotent and
# safe to run on every agent restart; when the node is already prepared it
# changes nothing and finishes in well under a second.
#
#   paguro-node-installer [install]   prepare the node (default)
#   paguro-node-installer check       report only, never change anything
#   paguro-node-installer uninstall   remove everything this installer added
#
# What "prepare" means (each step respects existing installations):
#   1. Preflight: architecture, kernel version/config, cgroup v2,
#      containerd >= 2.0, runc >= 1.2, nsenter/ip on the host.
#   2. Bundle (CRIU 4.2.1 with nftables, nft, crictl) -> /opt/paguro.
#      Symlinks in /usr/local/sbin only where the host has no usable tool
#      (criu >= 4.0, any nft, any crictl). Never downgrades a host install.
#   3. /etc/criu/runc.conf (ghost-limit, network-lock) – only if absent or
#      written by us earlier (marker line); a foreign file is left alone.
#   4. paguro-runc -> /usr/local/bin/paguro-runc (copy + rename, atomic).
#   5. containerd runtime handler "paguro" as a drop-in file in a directory
#      the main config imports. The drop-in uses the same schema version as
#      the main config (mixing v2 and v3 files silently drops settings in
#      containerd 2.0/2.1). The result is validated with `containerd config
#      dump` BEFORE containerd is restarted; any difference outside the
#      paguro handler rolls the change back.
#   6. containerd restart (only if the live daemon lacks the handler).
#   7. criu check (+ mem_dirty_track, network_lock_nftables).
#
# The installer never talks to the Kubernetes API. Hard failures exit
# non-zero, so the agent pod shows Init:Error with the report in its log.
#
# Environment (set by the Helm chart):
#   HOST_ROOT                    host root mount                    [/host]
#   PAGURO_HOST_EXEC             nsenter | chroot (tests)           [nsenter]
#   PAGURO_RUNTIME_HANDLER       containerd handler name            [paguro]
#   PAGURO_ANNOTATION_PREFIX     annotations passed to the OCI spec [paguro.dev/*]
#   PAGURO_RUNC_SRC              paguro-runc to install             [/stage/paguro-runc]
#   PAGURO_RUNC_DEST             host path of the wrapper           [/usr/local/bin/paguro-runc]
#   PAGURO_CONTAINERD_BIN        containerd binary (host path)      [auto]
#   PAGURO_CONTAINERD_CONFIG     main config (host path)            [auto]
#   PAGURO_CONTAINERD_UNIT       systemd unit to restart            [auto]
#   PAGURO_DROPIN_DIR            drop-in dir if no import exists    [<config dir>/conf.d]
#   PAGURO_RESTART_CONTAINERD    allow the restart                  [true]
#   PAGURO_CRIU_MIN_VERSION      host criu accepted from            [4.0]
#   PAGURO_REQUIRE_PRECOPY       missing soft-dirty is fatal        [false]
#   PAGURO_SKIP_KERNEL_CHECKS    tests only                         [false]
#   PAGURO_SKIP_CRIU_CHECK       tests only                         [false]
#   PAGURO_SKIP_LIVE_CHECK       tests only (no running containerd) [false]
set -uo pipefail
umask 022

MODE=${1:-install}
HOST_ROOT=${HOST_ROOT:-/host}
HOST_EXEC=${PAGURO_HOST_EXEC:-nsenter}
HANDLER=${PAGURO_RUNTIME_HANDLER:-paguro}
ANNOTATION=${PAGURO_ANNOTATION_PREFIX:-paguro.dev/*}
RUNC_SRC=${PAGURO_RUNC_SRC:-/stage/paguro-runc}
RUNC_DEST=${PAGURO_RUNC_DEST:-/usr/local/bin/paguro-runc}
CRIU_MIN=${PAGURO_CRIU_MIN_VERSION:-4.0}
RESTART=${PAGURO_RESTART_CONTAINERD:-true}
REQUIRE_PRECOPY=${PAGURO_REQUIRE_PRECOPY:-false}
SKIP_KERNEL=${PAGURO_SKIP_KERNEL_CHECKS:-false}
SKIP_CRIU_CHECK=${PAGURO_SKIP_CRIU_CHECK:-false}
SKIP_LIVE=${PAGURO_SKIP_LIVE_CHECK:-false}

BUNDLE_SRC=/opt/paguro          # inside the image
PREFIX=/opt/paguro              # on the host
SBIN=/usr/local/sbin
MARKER="# Managed by paguro-node-installer"
CFG_MARKER="# paguro-node-installer:"
STATE=/etc/paguro/node-installer.state

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------
declare -a REPORT=() WARNINGS=() ERRORS=()
CHANGED=0

log()  { printf '%s  %s\n' "$(date -u +%H:%M:%S)" "$*"; }
item() { REPORT+=("$(printf '%-22s %-10s %s' "$1" "$2" "$3")"); log "$1: $2 – $3"; }
warn() { WARNINGS+=("$*"); log "WARNING: $*"; }
err()  { ERRORS+=("$*"); log "ERROR: $*"; }
changed() { CHANGED=1; }
dry()  { [ "$MODE" = check ]; }

report() {
	echo
	echo "==================== paguro-node-installer report ===================="
	printf '%s\n' "node:  $(cat /proc/sys/kernel/hostname 2>/dev/null)  mode: $MODE"
	printf '%s\n' "${REPORT[@]}"
	if [ ${#WARNINGS[@]} -gt 0 ]; then
		echo "--- warnings"
		printf ' - %s\n' "${WARNINGS[@]}"
	fi
	if [ ${#ERRORS[@]} -gt 0 ]; then
		echo "--- errors (node is NOT ready for Paguro)"
		printf ' - %s\n' "${ERRORS[@]}"
		echo "======================================================================"
		return 1
	fi
	if [ $CHANGED -eq 1 ]; then echo "result: node prepared (changes applied)"; else echo "result: node already prepared, nothing changed"; fi
	echo "======================================================================"
}

finish() { report; exit $?; }
fatal()  { err "$*"; report; exit 1; }

# ---------------------------------------------------------------------------
# host access
# ---------------------------------------------------------------------------
# H <path>: host path as seen from this container.
H() { printf '%s%s' "$HOST_ROOT" "$1"; }

# hostrun <cmd...>: run a program in the host's namespaces (same view as
# containerd and runc). Tests use chroot into a fake host root instead.
hostrun() {
	case "$HOST_EXEC" in
	chroot) chroot "$HOST_ROOT" "$@" ;;
	*) nsenter -t 1 -m -u -i -n -p -- "$@" ;;
	esac
}

# ver_ge A B: true if version A >= B.
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

# Extract the first x.y[.z] from text.
semver() { grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1; }

# Atomic file install: copy to a temp name in the target dir, then rename.
# containerd may start a container (and exec the file) at any moment.
atomic_copy() { # src dst mode
	local dir; dir=$(dirname "$2")
	mkdir -p "$dir" || return 1
	cp "$1" "$dir/.$(basename "$2").paguro-new" &&
		chmod "$3" "$dir/.$(basename "$2").paguro-new" &&
		mv -f "$dir/.$(basename "$2").paguro-new" "$2"
}
atomic_write() { # dst mode  (content on stdin)
	cat > "$TMP/write" && atomic_copy "$TMP/write" "$1" "$2"
}
atomic_symlink() { # target linkpath
	mkdir -p "$(dirname "$2")" && ln -sfn "$1" "$2.paguro-new" && mv -fT "$2.paguro-new" "$2"
}

state_add() { # key=value lines in /etc/paguro/node-installer.state
	dry && return 0
	mkdir -p "$(H /etc/paguro)"
	touch "$(H "$STATE")"
	grep -qxF "$1" "$(H "$STATE")" || echo "$1" >> "$(H "$STATE")"
}

lock() {
	mkdir -p "$(H /run/paguro)"
	exec 9>"$(H /run/paguro/node-installer.lock)"
	flock -w 120 9 || fatal "another paguro-node-installer is running on this node"
}

# ---------------------------------------------------------------------------
# containerd config dump helpers (dump format is machine-generated and
# stable: one "[header]" per table, "key = value" lines below it)
# ---------------------------------------------------------------------------
# dump_section <file> <header without brackets>: lines of exactly that table.
dump_section() {
	awk -v want="[$2]" '
		/^[[:space:]]*\[/ { h=$0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", h); in_s = (h == want); next }
		in_s { sub(/^[[:space:]]+/, ""); if ($0 != "") print }
	' "$1"
}
# dump_get <file> <header> <key>: raw value (quotes stripped).
dump_get() {
	dump_section "$1" "$2" | awk -v k="$3" '
		{ split($0, a, " = "); if (a[1] == k) { v = substr($0, length(k) + 4); gsub(/^'\''|'\''$|^"|"$/, "", v); print v; exit } }'
}
# dump_strip <file> <handler>: dump without the handler tables and imports
# (everything that must be identical before and after our change).
dump_strip() {
	awk -v h="$2" '
		/^[[:space:]]*\[/ { t=$0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", t)
			skip = (index(t, ".runtimes." h "]") || index(t, ".runtimes." h ".") || index(t, ".runtimes.'\''" h "'\''")) }
		/^imports[[:space:]]*=/ { next }
		!skip { print }
	' "$1"
}

CRI_V3="plugins.'io.containerd.cri.v1.runtime'.containerd"

# ---------------------------------------------------------------------------
# step 1: preflight
# ---------------------------------------------------------------------------
kernel_config() {
	local rel; rel=$(uname -r)
	if [ -r /proc/config.gz ]; then zcat /proc/config.gz 2>/dev/null; return; fi
	for f in "/boot/config-$rel" "/lib/modules/$rel/config" "/usr/lib/modules/$rel/config"; do
		[ -r "$(H "$f")" ] && { cat "$(H "$f")"; return; }
	done
	return 1
}

preflight() {
	ARCH=$(uname -m)
	case "$ARCH" in
	x86_64) item arch ok "$ARCH" ;;
	aarch64) item arch warn "$ARCH"; warn "arm64: CRIU has no soft-dirty tracking on arm64 – no pre-copy, freeze time = full RAM dump" ;;
	*) err "unsupported architecture $ARCH (x86_64, aarch64)" ;;
	esac

	if [ "$SKIP_KERNEL" != true ]; then
		local kver; kver=$(uname -r | semver)
		if ver_ge "$kver" 5.15; then item kernel ok "$(uname -r)"; else err "kernel $(uname -r) is too old (need >= 5.15)"; fi
		if kernel_config > "$TMP/kconfig"; then
			kconf() { grep -q "^$1=y" "$TMP/kconfig"; }
			kconf CONFIG_CHECKPOINT_RESTORE || err "kernel lacks CONFIG_CHECKPOINT_RESTORE=y"
			if ! kconf CONFIG_MEM_SOFT_DIRTY; then
				if [ "$REQUIRE_PRECOPY" = true ]; then err "kernel lacks CONFIG_MEM_SOFT_DIRTY (pre-copy required by configuration)"
				else warn "kernel lacks CONFIG_MEM_SOFT_DIRTY – no pre-copy rounds, longer freeze"; fi
			fi
			kconf CONFIG_TIME_NS || warn "kernel lacks CONFIG_TIME_NS – restored containers see clock jumps (CLOCK_MONOTONIC)"
			kconf CONFIG_USERFAULTFD || log "info: CONFIG_USERFAULTFD not set (lazy restore unavailable; not used by default)"
			item kernel-config ok "checked (CHECKPOINT_RESTORE, MEM_SOFT_DIRTY, TIME_NS)"
		else
			warn "kernel config not readable (/proc/config.gz, /boot/config-*) – relying on criu check"
		fi
		local fs; fs=$(stat -f -c %T /sys/fs/cgroup 2>/dev/null)
		if [ "$fs" = cgroup2fs ]; then item cgroup ok v2; else err "cgroup v2 (unified hierarchy) required, found ${fs:-unknown}"; fi
	fi

	for tool in nsenter ip; do
		if p=$(hostrun sh -c "command -v $tool" 2>/dev/null) && [ -n "$p" ]; then :; else
			err "host has no '$tool' in PATH (util-linux / iproute2) – paguro-runc needs it"
		fi
	done
}

# ---------------------------------------------------------------------------
# step 1b: containerd + runc discovery
# ---------------------------------------------------------------------------
find_containerd_pid() {
	local d
	for d in /proc/[0-9]*; do
		[ "$(cat "$d/comm" 2>/dev/null)" = containerd ] && { basename "$d"; return 0; }
	done
	return 1
}

discover_containerd() {
	CTD_BIN=${PAGURO_CONTAINERD_BIN:-}
	CTD_CFG=${PAGURO_CONTAINERD_CONFIG:-}
	CTD_UNIT=${PAGURO_CONTAINERD_UNIT:-}
	CTD_PATH=""
	local pid
	if pid=$(find_containerd_pid); then
		[ -n "$CTD_BIN" ] || CTD_BIN=$(readlink "/proc/$pid/exe" | sed 's/ (deleted)$//')
		if [ -z "$CTD_CFG" ]; then
			# --config X | --config=X | -c X
			CTD_CFG=$(tr '\0' '\n' < "/proc/$pid/cmdline" | awk '
				prev { print; exit } /^(--config|-c)$/ { prev=1 } /^--config=/ { sub(/^--config=/, ""); print; exit }')
		fi
		[ -n "$CTD_UNIT" ] || CTD_UNIT=$(awk -F/ '/^0::/ { for (i = NF; i > 0; i--) if ($i ~ /\.service$/) { print $i; exit } }' "/proc/$pid/cgroup")
		CTD_PATH=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | sed -n 's/^PATH=//p')
	fi
	[ -n "$CTD_BIN" ] || CTD_BIN=$(hostrun sh -c 'command -v containerd' 2>/dev/null)
	[ -n "$CTD_BIN" ] || fatal "containerd not found (no running process, not in host PATH) – Paguro needs containerd >= 2.0"
	[ -n "$CTD_CFG" ] || CTD_CFG=/etc/containerd/config.toml
	[ -n "$CTD_UNIT" ] || CTD_UNIT=containerd.service
	# systemd default PATH for services without Environment=PATH
	[ -n "$CTD_PATH" ] || CTD_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

	CTD_VERSION=$(hostrun "$CTD_BIN" --version 2>/dev/null | grep -oE ' v?[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | tr -d ' v')
	[ -n "$CTD_VERSION" ] || fatal "cannot determine containerd version ($CTD_BIN --version)"
	if ver_ge "$CTD_VERSION" 2.0; then
		item containerd ok "$CTD_VERSION ($CTD_BIN, config $CTD_CFG, unit $CTD_UNIT)"
	else
		fatal "containerd $CTD_VERSION is too old – Paguro needs containerd >= 2.0 (config schema v3, CRI annotations)"
	fi
	case "$CTD_CFG" in
	/var/lib/rancher/*) RANCHER=1; warn "k3s/RKE2 detected: containerd config is regenerated on every start; only the imports drop-in directory of the generated config survives" ;;
	*) RANCHER=0 ;;
	esac
}

containerd_dump() { # out-file [config]
	hostrun "$CTD_BIN" --config "${2:-$CTD_CFG}" config dump > "$1" 2> "$TMP/dump.err"
}

discover_runtime() {
	containerd_dump "$TMP/before.toml" || fatal "containerd config dump failed: $(tail -c 400 "$TMP/dump.err")"
	DEFAULT_RT=$(dump_get "$TMP/before.toml" "$CRI_V3" default_runtime_name)
	[ -n "$DEFAULT_RT" ] || DEFAULT_RT=runc
	local opts="$CRI_V3.runtimes.$DEFAULT_RT.options"
	SYSTEMD_CGROUP=$(dump_get "$TMP/before.toml" "$opts" SystemdCgroup)
	[ -n "$SYSTEMD_CGROUP" ] || SYSTEMD_CGROUP=false
	BASE_SPEC=$(dump_get "$TMP/before.toml" "$CRI_V3.runtimes.$DEFAULT_RT" base_runtime_spec)
	RUNC_BIN=$(dump_get "$TMP/before.toml" "$opts" BinaryName)
	# Default handler may be a wrapper (nvidia-container-runtime): fall back to runc.
	if [ -z "$RUNC_BIN" ] || [ "$(basename "$RUNC_BIN")" != runc ]; then
		RUNC_BIN=$(hostrun sh -c 'command -v runc' 2>/dev/null)
	fi
	[ -n "$RUNC_BIN" ] || { err "runc not found on the host"; return; }
	local rv; rv=$(hostrun "$RUNC_BIN" --version 2>/dev/null | head -n1 | semver)
	if [ -n "$rv" ] && ver_ge "$rv" 1.2; then
		item runc ok "$rv ($RUNC_BIN)"
	else
		err "runc ${rv:-unknown} at $RUNC_BIN – Paguro needs runc >= 1.2"
	fi
	log "default runtime '$DEFAULT_RT': SystemdCgroup=$SYSTEMD_CGROUP base_runtime_spec=${BASE_SPEC:-<none>}"
}

# ---------------------------------------------------------------------------
# step 2: bundle + tools
# ---------------------------------------------------------------------------
# host_has <tool> <min|->: does the host provide a usable <tool> itself?
host_has() {
	local foreign fv
	foreign=$(find_foreign "$1") || return 1
	[ "$2" = - ] && return 0
	fv=$(hostrun "$foreign" --version 2>&1 | semver)
	[ -n "$fv" ] && ver_ge "$fv" "$2"
}

install_bundle() {
	# Always installed into its own prefix, even if the host has CRIU: the
	# bundled CRIU carries Paguro's patches (build/criu-patches), and the
	# restore wrapper runs the lazy-pages daemon only with a CRIU that
	# provably has them (criu-patches.sha256) – an unpatched host CRIU hangs
	# a post-copy restore after pre-copy. The bundle never replaces host
	# tools: links into /usr/local/sbin are only created for missing tools
	# (step "tools" below).
	if cmp -s "$BUNDLE_SRC/MANIFEST" "$(H $PREFIX/MANIFEST)" &&
		(cd "$(H $PREFIX)" && sha256sum -c --quiet MANIFEST >/dev/null 2>&1); then
		item bundle ok "$PREFIX up to date ($(cat "$BUNDLE_SRC/VERSION"))"
		return
	fi
	if dry; then item bundle missing "$PREFIX would be installed/updated"; return; fi
	local f
	# Libraries before binaries, manifest last: an interrupted copy is
	# detected (manifest mismatch) and repaired on the next run.
	for f in $(awk '{print $2}' "$BUNDLE_SRC/MANIFEST" | sort -r); do
		atomic_copy "$BUNDLE_SRC/$f" "$(H "$PREFIX/$f")" "$(stat -c %a "$BUNDLE_SRC/$f")" ||
			fatal "copy $f to $PREFIX failed"
	done
	# Files of an older bundle version that are no longer shipped.
	if [ -f "$(H $PREFIX/MANIFEST)" ]; then
		for f in $(awk '{print $2}' "$(H $PREFIX/MANIFEST)"); do
			grep -q " $f\$" "$BUNDLE_SRC/MANIFEST" || rm -f "$(H "$PREFIX/$f")"
		done
	fi
	cp "$BUNDLE_SRC/VERSION" "$(H $PREFIX/VERSION)"
	# Fingerprint of the CRIU patches in this bundle; the restore wrapper
	# only uses lazy pages with a CRIU that has them.
	cp "$BUNDLE_SRC/criu-patches.sha256" "$(H $PREFIX/criu-patches.sha256)"
	atomic_copy "$BUNDLE_SRC/MANIFEST" "$(H $PREFIX/MANIFEST)" 0644
	changed
	item bundle installed "$PREFIX ($(cat "$BUNDLE_SRC/VERSION"), nft, crictl)"
}

# find_foreign <tool>: first <tool> in containerd's PATH that is not our
# symlink. Prints the host path.
find_foreign() {
	local d p
	IFS=: read -ra dirs <<< "$CTD_PATH"
	for d in "${dirs[@]}"; do
		p="$d/$1"
		[ -e "$(H "$p")" ] || [ -L "$(H "$p")" ] || continue
		[ "$(readlink "$(H "$p")")" = "$PREFIX/bin/$1" ] && continue
		[ -x "$(H "$p")" ] && { echo "$p"; return 0; }
	done
	return 1
}

# provide <tool> <min-version|-> <version-cmd-args>
# Uses a host install if present (and new enough), else links ours into
# /usr/local/sbin. Sets EFFECTIVE_<tool>.
provide() {
	local tool=$1 min=$2 vflag=$3 foreign fv link ours
	link="$SBIN/$tool"; ours="$PREFIX/bin/$tool"
	if foreign=$(find_foreign "$tool"); then
		fv=$(hostrun "$foreign" $vflag 2>&1 | semver)
		if [ "$min" = - ] || { [ -n "$fv" ] && ver_ge "$fv" "$min"; }; then
			# Host install wins. A stale symlink of ours would shadow it.
			if [ "$(readlink "$(H "$link")" 2>/dev/null)" = "$ours" ] && ! dry; then
				rm -f "$(H "$link")"; changed
				item "$tool" changed "removed $link, host $foreign ${fv:-} is used"
			else
				item "$tool" ok "host install $foreign ${fv:-}"
			fi
			eval "EFFECTIVE_$tool=\$foreign"
			return
		fi
		warn "host $tool $foreign ${fv:-unknown} is older than $min – using the bundled one"
	fi
	if [ "$(readlink "$(H "$link")" 2>/dev/null)" = "$ours" ]; then
		item "$tool" ok "bundled ($link -> $ours)"
	elif dry; then
		item "$tool" missing "would link $link -> $ours"
	else
		if [ -e "$(H "$link")" ] && [ ! -L "$(H "$link")" ]; then
			# an outdated foreign binary exactly where our link goes
			mv -f "$(H "$link")" "$(H "$link.pre-paguro")"
			warn "moved outdated $link to $link.pre-paguro"
			state_add "moved=$link"
		fi
		atomic_symlink "$ours" "$(H "$link")" || fatal "cannot create $link"
		state_add "symlink=$link"
		changed
		item "$tool" installed "$link -> $ours"
	fi
	eval "EFFECTIVE_$tool=\$link"
}

check_path() {
	# paguro-runc runs with containerd's environment and calls these by name.
	local t d found
	IFS=: read -ra dirs <<< "$CTD_PATH"
	for t in criu nft nsenter ip; do
		found=""
		for d in "${dirs[@]}"; do [ -x "$(H "$d/$t")" ] && { found="$d/$t"; break; }; done
		[ -n "$found" ] || err "'$t' is not reachable via containerd's PATH ($CTD_PATH)"
	done
}

# ---------------------------------------------------------------------------
# step 3: /etc/criu/runc.conf
# ---------------------------------------------------------------------------
install_runc_conf() {
	local f; f=$(H /etc/criu/runc.conf)
	local lock=nftables
	if [ "$SKIP_CRIU_CHECK" != true ] && ! hostrun "$EFFECTIVE_criu" check --feature network_lock_nftables >/dev/null 2>&1; then
		lock=iptables
		warn "CRIU network_lock_nftables unsupported on this kernel – runc.conf uses network-lock iptables"
	fi
	cat > "$TMP/runc.conf" <<-EOF
	$MARKER – delete this line to take ownership.
	# CRIU options that runc passes on every checkpoint/restore (also for
	# kubelet checkpoints). Format: long option without "--".
	# Keep deleted-but-open files up to 1 GiB in the image
	ghost-limit 1G
	# Lock the network during dump/restore with nftables (not iptables)
	network-lock $lock
	EOF
	if [ -f "$f" ] && ! head -n1 "$f" | grep -qF "$MARKER"; then
		item runc.conf ok "foreign file kept ($(grep -E '^(network-lock|ghost-limit)' "$f" | tr '\n' ' '))"
		grep -q '^network-lock' "$f" || warn "/etc/criu/runc.conf (not ours) has no network-lock option"
		return
	fi
	if cmp -s "$TMP/runc.conf" "$f"; then item runc.conf ok "up to date"; return; fi
	if dry; then item runc.conf missing "would write /etc/criu/runc.conf"; return; fi
	atomic_copy "$TMP/runc.conf" "$f" 0644 || fatal "cannot write /etc/criu/runc.conf"
	state_add "file=/etc/criu/runc.conf"
	changed; item runc.conf installed "network-lock $lock, ghost-limit 1G"
}

# ---------------------------------------------------------------------------
# step 4: paguro-runc
# ---------------------------------------------------------------------------
install_paguro_runc() {
	if [ ! -f "$RUNC_SRC" ]; then
		item paguro-runc skipped "no source at $RUNC_SRC"
		[ -x "$(H "$RUNC_DEST")" ] || err "$RUNC_DEST missing on the host and no paguro-runc to install"
		return
	fi
	if cmp -s "$RUNC_SRC" "$(H "$RUNC_DEST")"; then item paguro-runc ok "$RUNC_DEST up to date"; return; fi
	if dry; then item paguro-runc missing "would install $RUNC_DEST"; return; fi
	atomic_copy "$RUNC_SRC" "$(H "$RUNC_DEST")" 0755 || fatal "cannot install $RUNC_DEST"
	state_add "file=$RUNC_DEST"
	changed; item paguro-runc installed "$RUNC_DEST"

	# paguro-runc finds runc via a fixed candidate list; tell it about a
	# non-standard location (k3s/RKE2 ship runc in their data dir).
	local first="" c
	for c in /usr/local/sbin/runc /usr/local/bin/runc /usr/sbin/runc /usr/bin/runc; do
		[ -x "$(H "$c")" ] && { first=$c; break; }
	done
	if [ -n "${RUNC_BIN:-}" ] && [ "$first" != "$RUNC_BIN" ] && [ ! -f "$(H /etc/paguro/runc-path)" ]; then
		echo "$RUNC_BIN" | atomic_write "$(H /etc/paguro/runc-path)" 0644
		state_add "file=/etc/paguro/runc-path"
		item runc-path installed "/etc/paguro/runc-path -> $RUNC_BIN"
	fi
}

# ---------------------------------------------------------------------------
# step 5: containerd runtime handler
# ---------------------------------------------------------------------------
# Top-level part of the main config (everything before the first table).
cfg_toplevel() { awk '/^[[:space:]]*\[/ { exit } { print }' "$1"; }
cfg_version() { cfg_toplevel "$1" | sed -nE 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*([0-9]+).*/\1/p' | head -n1; }
# Import entries (one per line, unquoted), also for multi-line arrays.
cfg_imports() {
	cfg_toplevel "$1" | awk '
		/^[[:space:]]*imports[[:space:]]*=/ { on=1 }
		on { line = line $0; if (index($0, "]")) exit }
		END { sub(/^[^[]*\[/, "", line); sub(/\].*$/, "", line); n = split(line, a, ",")
			for (i = 1; i <= n; i++) { v = a[i]; gsub(/^[[:space:]]*["'\'']|["'\''][[:space:]]*$/, "", v); if (v != "") print v } }'
}

handler_ok() { # dump-file: handler present with our binary + annotations?
	local rt="$CRI_V3.runtimes.$HANDLER"
	[ "$(dump_get "$1" "$rt.options" BinaryName)" = "$RUNC_DEST" ] &&
		dump_get "$1" "$rt" pod_annotations | grep -qF "'$ANNOTATION'" &&
		dump_get "$1" "$rt" container_annotations | grep -qF "'$ANNOTATION'"
}

render_dropin() { # schema-version
	local v=$1 base
	if [ "$v" -ge 3 ]; then base="plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.$HANDLER"
	else base="plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.$HANDLER"; fi
	cat <<-EOF
	$MARKER – changes are overwritten.
	# containerd runtime handler for the RuntimeClass "$HANDLER": the same runc
	# shim as the default handler "$DEFAULT_RT", but paguro-runc as the OCI
	# runtime (restores checkpoints instead of creating fresh containers).
	# Schema version matches the main config $CTD_CFG.
	version = $v

	[$base]
	  runtime_type = 'io.containerd.runc.v2'
	  pod_annotations = ['$ANNOTATION']
	  container_annotations = ['$ANNOTATION']
	EOF
	[ -n "$BASE_SPEC" ] && echo "  base_runtime_spec = '$BASE_SPEC'"
	cat <<-EOF

	[$base.options]
	  BinaryName = '$RUNC_DEST'
	  SystemdCgroup = $SYSTEMD_CGROUP
	EOF
}

# Add our glob to the top-level imports of the main config (idempotent).
add_import() { # cfg-file glob
	local f=$1 glob=$2
	if cfg_toplevel "$f" | grep -qE '^[[:space:]]*imports[[:space:]]*='; then
		# prepend as first element; TOML allows the trailing comma for "[]"
		awk -v g="$glob" -v m="$CFG_MARKER added \"$glob\" to imports" '
			!done && /^[[:space:]]*\[/ { top_end=1 }
			!done && !top_end && /^[[:space:]]*imports[[:space:]]*=[[:space:]]*\[/ {
				print m; sub(/\[/, "[\"" g "\", "); done=1 }
			{ print }' "$f"
	else
		awk -v g="$glob" -v m="$CFG_MARKER added imports line" '
			!done && /^[[:space:]]*version[[:space:]]*=/ { print; print m; print "imports = [\"" g "\"]"; done=1; next }
			{ print }' "$f"
	fi
}

restore_file() { # backup original
	if [ -f "$1" ]; then cp -p "$1" "$2"; else rm -f "$2"; fi
}

install_handler() {
	local cfg; cfg=$(H "$CTD_CFG")
	local cfgdir; cfgdir=$(dirname "$CTD_CFG")
	local ver dropdir="" glob="" need_import=0 i

	if [ -f "$cfg" ]; then
		ver=$(cfg_version "$cfg")
		[ -n "$ver" ] || fatal "$CTD_CFG has no 'version' line (schema v1) – migrate it first: containerd config migrate"
		while read -r i; do
			[ -n "$i" ] || continue
			case "$i" in /*) ;; *) i="$cfgdir/$i" ;; esac
			case "$i" in */\*.toml) dropdir=$(dirname "$i"); glob=$i; break ;; esac
		done < <(cfg_imports "$cfg")
	else
		ver=$(hostrun "$CTD_BIN" config default 2>/dev/null | sed -nE 's/^version = ([0-9]+).*/\1/p' | head -n1)
		ver=${ver:-3}
	fi
	if [ -z "$dropdir" ]; then
		dropdir=${PAGURO_DROPIN_DIR:-$cfgdir/conf.d}
		glob="$dropdir/*.toml"
		need_import=1
	fi
	local dropin="$dropdir/$HANDLER.toml"
	render_dropin "$ver" > "$TMP/dropin.toml"

	local ours=0
	[ -f "$(H "$dropin")" ] && head -n1 "$(H "$dropin")" | grep -qF "$MARKER" && ours=1

	if [ $ours -eq 0 ] && grep -q "\.runtimes\.$HANDLER\]" "$TMP/before.toml"; then
		if handler_ok "$TMP/before.toml"; then
			local sc; sc=$(dump_get "$TMP/before.toml" "$CRI_V3.runtimes.$HANDLER.options" SystemdCgroup)
			[ "${sc:-false}" = "$SYSTEMD_CGROUP" ] ||
				warn "existing handler '$HANDLER' has SystemdCgroup=${sc:-false}, default runtime has $SYSTEMD_CGROUP"
			item containerd-handler ok "'$HANDLER' already configured outside the installer – left alone"
			return
		fi
		fatal "containerd already has a runtime '$HANDLER' that is not ours and not usable (BinaryName must be $RUNC_DEST, pod/container_annotations must contain '$ANNOTATION') – fix or remove it"
	fi
	if [ $ours -eq 1 ] && [ $need_import -eq 0 ] && cmp -s "$TMP/dropin.toml" "$(H "$dropin")"; then
		item containerd-handler ok "drop-in $dropin up to date"
		return
	fi
	if dry; then
		item containerd-handler missing "would write $dropin$([ $need_import -eq 1 ] && echo " and add an imports entry to $CTD_CFG")"
		return
	fi

	# --- apply, validate, roll back on any surprise ---
	mkdir -p "$(H "$dropdir")"
	restore_file "$(H "$dropin")" "$TMP/dropin.orig"
	[ -f "$cfg" ] && cp -p "$cfg" "$TMP/config.orig"
	rollback() {
		restore_file "$TMP/dropin.orig" "$(H "$dropin")"
		[ -f "$TMP/config.orig" ] && cp -p "$TMP/config.orig" "$cfg"
		[ -f "$TMP/config.orig" ] || { [ $need_import -eq 1 ] && rm -f "$cfg"; }
	}
	atomic_copy "$TMP/dropin.toml" "$(H "$dropin")" 0644 || fatal "cannot write $dropin"
	if [ $need_import -eq 1 ]; then
		if [ -f "$cfg" ]; then
			cp -p "$cfg" "$cfg.pre-paguro"
			add_import "$cfg" "$glob" > "$TMP/config.new"
		else
			printf '%s\nversion = %s\n%s added imports line\nimports = ["%s"]\n' \
				"$CFG_MARKER created this file (containerd defaults + imports)" "$ver" "$CFG_MARKER" "$glob" > "$TMP/config.new"
		fi
		atomic_copy "$TMP/config.new" "$cfg" 0644 || { rollback; fatal "cannot update $CTD_CFG"; }
	fi

	if ! containerd_dump "$TMP/after.toml"; then
		rollback; fatal "containerd rejects the new config: $(tail -c 400 "$TMP/dump.err") – rolled back"
	fi
	if ! handler_ok "$TMP/after.toml"; then
		rollback; fatal "handler '$HANDLER' not visible in containerd config dump after writing $dropin – rolled back"
	fi
	dump_strip "$TMP/before.toml" "$HANDLER" > "$TMP/before.strip"
	dump_strip "$TMP/after.toml" "$HANDLER" > "$TMP/after.strip"
	if ! diff -u "$TMP/before.strip" "$TMP/after.strip" > "$TMP/dump.diff"; then
		cat "$TMP/dump.diff"
		rollback; fatal "adding the drop-in changed other containerd settings (diff above) – rolled back"
	fi
	state_add "dropin=$dropin"
	[ $need_import -eq 1 ] && state_add "import=$CTD_CFG|$glob"
	changed
	item containerd-handler installed "$dropin (schema v$ver, SystemdCgroup=$SYSTEMD_CGROUP)$([ $need_import -eq 1 ] && echo ", imports added to $CTD_CFG (backup $CTD_CFG.pre-paguro)")"
	[ $need_import -eq 1 ] && [ "${RANCHER:-0}" = 1 ] &&
		warn "k3s/RKE2 regenerates $CTD_CFG – the imports entry will be lost on restart; use a k3s version whose generated config imports config-v3.toml.d"
	[ $need_import -eq 1 ] && { [ -x "$(H /usr/bin/nodeadm)" ] || [ -d "$(H /etc/eks)" ]; } &&
		warn "EKS nodeadm regenerates $CTD_CFG on every boot – add the imports line via NodeConfig spec.containerd.config to avoid a containerd restart per boot (see docs/INSTALL.md)"
	return 0
}

# ---------------------------------------------------------------------------
# step 6: live daemon
# ---------------------------------------------------------------------------
live_has_handler() {
	local sock
	sock=$(dump_get "$TMP/before.toml" grpc address)
	sock=${sock:-/run/containerd/containerd.sock}
	hostrun "${EFFECTIVE_crictl:-$PREFIX/bin/crictl}" --runtime-endpoint "unix://$sock" info 2>/dev/null > "$TMP/crictl-info.json" || return 2
	grep -qE "\"$HANDLER\"[[:space:]]*:[[:space:]]*\\{" "$TMP/crictl-info.json"
}

ensure_live() {
	[ "$SKIP_LIVE" = true ] && { item containerd-live skipped "PAGURO_SKIP_LIVE_CHECK"; return; }
	live_has_handler; local rc=$?
	if [ $rc -eq 0 ]; then item containerd-live ok "running containerd serves handler '$HANDLER'"; return; fi
	if [ $rc -eq 2 ]; then warn "cannot query the running containerd via CRI (crictl info) – restart decision based on config only"; fi
	if dry; then item containerd-live missing "running containerd does not serve '$HANDLER' – restart needed"; return; fi
	if [ "$RESTART" != true ]; then
		err "containerd must be restarted to load handler '$HANDLER' (PAGURO_RESTART_CONTAINERD=false): systemctl restart $CTD_UNIT"
		return
	fi
	log "restarting $CTD_UNIT (running containers survive, kubelet reconnects)"
	hostrun systemctl restart "$CTD_UNIT" || { err "systemctl restart $CTD_UNIT failed"; return; }
	local _
	for _ in $(seq 1 60); do
		live_has_handler && break
		sleep 1
	done
	if live_has_handler; then changed; item containerd-live restarted "$CTD_UNIT now serves '$HANDLER'"
	else err "containerd restarted but still does not serve '$HANDLER' – check: containerd config dump | grep runtimes.$HANDLER"; fi
}

# ---------------------------------------------------------------------------
# step 7: criu check
# ---------------------------------------------------------------------------
criu_checks() {
	[ "$SKIP_CRIU_CHECK" = true ] && { item criu-check skipped "PAGURO_SKIP_CRIU_CHECK"; return; }
	local out
	out=$(hostrun "$EFFECTIVE_criu" check 2>&1)
	if [ $? -eq 0 ] && echo "$out" | grep -q "Looks good"; then
		item criu-check ok "$(echo "$out" | tail -n1)"
	else
		echo "$out" | tail -n 20
		err "criu check failed – the kernel lacks checkpoint/restore features (output above)"
	fi
	if hostrun "$EFFECTIVE_criu" check --feature mem_dirty_track >/dev/null 2>&1; then
		item criu-precopy ok "mem_dirty_track"
	elif [ "$REQUIRE_PRECOPY" = true ]; then
		err "criu: mem_dirty_track unsupported – no pre-copy (required by configuration)"
	else
		item criu-precopy warn "mem_dirty_track unsupported"; warn "no pre-copy on this node (soft-dirty tracking missing)"
	fi
	if hostrun "$EFFECTIVE_criu" check --feature network_lock_nftables >/dev/null 2>&1; then
		item criu-netlock ok "network_lock_nftables"
	else
		item criu-netlock warn "network_lock_nftables unsupported (iptables lock is used)"
	fi
}

# ---------------------------------------------------------------------------
# uninstall: undo exactly what the state file records
# ---------------------------------------------------------------------------
uninstall() {
	local st; st=$(H "$STATE")
	[ -f "$st" ] || { item uninstall ok "nothing recorded in $STATE"; finish; }
	local line k v restart=0
	while read -r line; do
		k=${line%%=*}; v=${line#*=}
		case "$k" in
		symlink)
			[ "$(readlink "$(H "$v")")" = "$PREFIX/bin/$(basename "$v")" ] && rm -f "$(H "$v")" && item "$v" removed symlink ;;
		moved)
			[ -e "$(H "$v")" ] || { mv -f "$(H "$v.pre-paguro")" "$(H "$v")" && item "$v" restored "from $v.pre-paguro"; } ;;
		file)
			case "$v" in
			/etc/criu/runc.conf) head -n1 "$(H "$v")" 2>/dev/null | grep -qF "$MARKER" && rm -f "$(H "$v")" && item "$v" removed "" ;;
			*) rm -f "$(H "$v")" && item "$v" removed "" ;;
			esac ;;
		dropin)
			head -n1 "$(H "$v")" 2>/dev/null | grep -qF "$MARKER" && rm -f "$(H "$v")" && restart=1 && item "$v" removed "containerd drop-in" ;;
		import)
			local cf=${v%%|*} g=${v#*|} f; f=$(H "$cf")
			[ -f "$f" ] || continue
			if head -n1 "$f" | grep -qF "$CFG_MARKER created this file"; then
				rm -f "$f" && restart=1 && item "$cf" removed "created by the installer"
				continue
			fi
			awk -v g="$g" -v m="$CFG_MARKER" '
				index($0, m " added imports line") == 1 { drop_next=1; next }
				index($0, m " added \"" g "\" to imports") == 1 { strip_next=1; next }
				drop_next { drop_next=0; next }
				strip_next { sub("\"" g "\", ", ""); strip_next=0 }
				{ print }' "$f" > "$TMP/cfg.clean" && atomic_copy "$TMP/cfg.clean" "$f" 0644 && restart=1 &&
				item "$cf" cleaned "imports entry $g removed" ;;
		esac
	done < "$st"
	rm -rf "$(H $PREFIX)" "$(H "$STATE")"
	item "$PREFIX" removed "bundle"
	if [ $restart -eq 1 ] && [ "$RESTART" = true ] && [ "$SKIP_LIVE" != true ]; then
		hostrun systemctl restart "$CTD_UNIT" && item containerd restarted "$CTD_UNIT"
	elif [ $restart -eq 1 ]; then
		warn "restart containerd to unload handler '$HANDLER': systemctl restart $CTD_UNIT"
	fi
	finish
}

# ---------------------------------------------------------------------------
main() {
	case "$MODE" in install | check | uninstall) ;; *) echo "usage: $0 [install|check|uninstall]" >&2; exit 2 ;; esac
	log "paguro-node-installer $MODE (bundle $(cat "$BUNDLE_SRC/VERSION" 2>/dev/null), host root $HOST_ROOT, exec $HOST_EXEC)"
	[ -d "$HOST_ROOT/etc" ] || fatal "host root not mounted at $HOST_ROOT"
	lock
	if [ "$MODE" = uninstall ]; then discover_containerd; uninstall; fi

	preflight
	discover_containerd
	discover_runtime
	# Preflight errors: stop before touching anything.
	[ ${#ERRORS[@]} -eq 0 ] || finish

	install_bundle
	provide criu "$CRIU_MIN" --version
	provide nft - --version
	provide crictl - --version
	EFFECTIVE_criu=${EFFECTIVE_criu:-$PREFIX/bin/criu}
	install_runc_conf
	install_paguro_runc
	install_handler
	check_path
	ensure_live
	criu_checks
	finish
}

main
