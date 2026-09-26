#!/bin/sh
# Starts a local PostgreSQL for the test suite without Docker: the same
# pg_hba.conf, settings and certificates as tests/compose.yml, in a
# throwaway data directory. Needs initdb/pg_ctl on PATH (or PG_BIN).
#
#   tests/local-server.sh start [port]   # default 5432
#   zig build test -Dtest_port=<port>
#   tests/local-server.sh stop
set -eu

cd "$(dirname "$0")"
DATA="${PG_TEST_DATA:-$PWD/.local-pgdata}"
BIN="${PG_BIN:-}"
[ -n "$BIN" ] && BIN="$BIN/"
PORT="${2:-5432}"

case "${1:-}" in
start)
	[ -f server.key ] || (cd .. && make ssl)
	if [ ! -d "$DATA" ]; then
		pwfile="$(mktemp)"
		echo postgres >"$pwfile"
		"${BIN}initdb" -D "$DATA" -U postgres --pwfile="$pwfile" -E UTF8 --locale=C >/dev/null
		rm -f "$pwfile"
		cp pg_hba.conf "$DATA/pg_hba.conf"
		cat >>"$DATA/postgresql.conf" <<EOF
port = $PORT
listen_addresses = 'localhost'
unix_socket_directories = ''
max_connections = 30
timezone = 'UTC'
datestyle = 'iso, mdy'
fsync = off
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
EOF
	fi
	# Always the current certs: `make ssl` regenerates them (and root.crt).
	# No ssl_ca_file: with it the server sends a TLS CertificateRequest,
	# which the default std TLS client cannot answer.
	cp server.crt server.key "$DATA/"
	chmod 600 "$DATA/server.key"
	"${BIN}pg_ctl" -D "$DATA" -l "$DATA/server.log" -w start
	;;
stop)
	"${BIN}pg_ctl" -D "$DATA" -m fast stop
	;;
*)
	echo "usage: $0 start [port] | stop" >&2
	exit 2
	;;
esac
