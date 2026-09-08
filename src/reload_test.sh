#!/bin/sh
set -eu

bin=${1:-./sysmond}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/sysmon-reload-XXXXXX")
conf="$tmp/sysmon.conf"
log="$tmp/sysmond.log"
pid=

cleanup()
{
	if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
		kill -TERM "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
	rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM

# A root-started test drops to nobody. Keep the path traversable after
# the drop so a valid second reload tests reload, not permissions.
chmod 755 "$tmp"

write_valid()
{
	cat >"$conf" <<EOF2
root = "root";
config statedir "$tmp/state";
config noheartbeat;
config queuetime 1;
config maxqueued 1;
object root {
	ip "127.0.0.1";
	type tcp;
	port 9;
};
EOF2
	chmod 644 "$conf"
}

write_missing_root()
{
	cat >"$conf" <<EOF2
root = "not-present";
config statedir "$tmp/state";
config noheartbeat;
config queuetime 1;
config maxqueued 1;
object root {
	ip "127.0.0.1";
	type tcp;
	port 9;
};
EOF2
	chmod 644 "$conf"
}

write_missing_dependency()
{
	cat >"$conf" <<EOF2
root = "root";
config statedir "$tmp/state";
config noheartbeat;
config queuetime 1;
config maxqueued 2;
object root {
	ip "127.0.0.1";
	type tcp;
	port 9;
};
object child {
	ip "127.0.0.1";
	type tcp;
	port 9;
	dep "not-present";
};
EOF2
	chmod 644 "$conf"
}

write_missing_include()
{
	cat >"$conf" <<EOF2
include "$tmp/not-present.conf";
root = "root";
config statedir "$tmp/state";
config noheartbeat;
config queuetime 1;
config maxqueued 1;
object root {
	ip "127.0.0.1";
	type tcp;
	port 9;
};
EOF2
	chmod 644 "$conf"
}

write_valid_with_spawn()
{
	cat >"$conf" <<EOF2
root = "root";
config statedir "$tmp/state";
config noheartbeat;
config queuetime 1;
config maxqueued 1;
spawns {
	old "/bin/true"
};
object root {
	ip "127.0.0.1";
	type tcp;
	port 9;
	spawn old;
};
EOF2
	chmod 644 "$conf"
}

write_missing_spawn()
{
	cat >"$conf" <<EOF2
root = "root";
config statedir "$tmp/state";
config noheartbeat;
config queuetime 1;
config maxqueued 1;
object root {
	ip "127.0.0.1";
	type tcp;
	port 9;
	spawn old;
};
EOF2
	chmod 644 "$conf"
}

check_count()
{
	grep -c "handle_retval:dequeued" "$log" 2>/dev/null || true
}

wait_for_more_checks()
{
	before=$1
	i=0
	while [ "$i" -lt 10 ]; do
		after=$(check_count)
		if [ "$after" -gt "$before" ]; then
			return 0
		fi
		if ! kill -0 "$pid" 2>/dev/null; then
			echo "sysmond died while waiting for checks" >&2
			cat "$log" >&2
			return 1
		fi
		sleep 1
		i=$((i + 1))
	done
	echo "sysmond stopped checking after a rejected reload" >&2
	cat "$log" >&2
	return 1
}

expect_start_rejected()
{
	writer=$1
	label=$2
	badlog="$tmp/bad-$label.log"

	"$writer"
	"$bin" -d -D -l -i -p 0 -f "$conf" >"$badlog" 2>&1 &
	badpid=$!
	sleep 2
	if kill -0 "$badpid" 2>/dev/null; then
		echo "sysmond accepted $label" >&2
		kill -TERM "$badpid" 2>/dev/null || true
		wait "$badpid" 2>/dev/null || true
		cat "$badlog" >&2
		exit 1
	fi
	if wait "$badpid" 2>/dev/null; then
		echo "invalid startup exited successfully: $label" >&2
		exit 1
	else
		status=$?
		if [ "$status" -ne 1 ]; then
			echo "invalid startup crashed or was signalled (status $status): $label" >&2
			cat "$badlog" >&2
			exit 1
		fi
	fi
}

# Structurally incomplete configs must not become a daemon that appears
# healthy while monitoring only a subset (or none) of what was declared.
expect_start_rejected write_missing_root "a configuration with no root"
expect_start_rejected write_missing_dependency "an undefined dependency"
expect_start_rejected write_missing_include "a missing include"
expect_start_rejected write_missing_spawn "an undefined named spawn"

# Start with a named spawn present, so a later config that merely
# references the removed name proves definitions do not leak across loads.
write_valid_with_spawn
"$bin" -d -D -l -i -p 0 -f "$conf" >"$log" 2>&1 &
pid=$!
wait_for_more_checks 0

# Wait for evidence that the specific signal was processed, not merely a
# check that may have completed before the daemon saw SIGHUP.
wait_for_log_count()
{
	pattern=$1
	before=$2
	i=0
	while [ "$i" -lt 20 ]; do
		after=$(grep -c "$pattern" "$log" || true)
		[ "$after" -gt "$before" ] && return 0
		kill -0 "$pid" 2>/dev/null || break
		sleep 1
		i=$((i + 1))
	done
	echo "did not observe $pattern" >&2
	cat "$log" >&2
	return 1
}

for writer in write_missing_root write_missing_dependency write_missing_include write_missing_spawn; do
	rejections=$(grep -c "Reload rejected" "$log" || true)
	"$writer"
	kill -HUP "$pid"
	wait_for_log_count "Reload rejected" "$rejections"
	before=$(check_count)
	wait_for_more_checks "$before"
done

before=$(grep -c "Done reloading new config file" "$log" || true)
write_valid
kill -HUP "$pid"
wait_for_log_count "Done reloading new config file" "$before"
before=$(check_count)
wait_for_more_checks "$before"

kill -TERM "$pid"
wait "$pid"
pid=
echo "reload: rejected signals processed, checks continued, valid reload committed"

# A valid managed configuration must not be rejected just because the seed
# is not runnable. The seed still supplies the locked state directory.
write_valid
mkdir -p "$tmp/state/gen-0000000001"
cp "$conf" "$tmp/state/gen-0000000001/sysmon.conf"
printf 'sysmon.conf\n' >"$tmp/state/main"
ln -s gen-0000000001 "$tmp/state/current"
write_missing_root
"$bin" -t -l -i -f "$conf" >"$tmp/managed.log" 2>&1 || {
	cat "$tmp/managed.log" >&2
	exit 1
}
echo "reload: valid managed config accepted with an unrunnable seed"
