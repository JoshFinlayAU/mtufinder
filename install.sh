#!/usr/bin/env bash
# Install mtufinder so it can run without sudo.
#
# Linux: prefers setcap (cap_net_raw) over setuid. Falls back to setuid if
#        setcap isn't available or the filesystem doesn't support capabilities.
# macOS: setuid root, owner root, mode 4755.
# Windows: not supported here -- run from an elevated shell.
#
# Usage: ./install.sh [path-to-binary]   (defaults to ./mtufinder)

set -euo pipefail

BIN="${1:-./mtufinder}"

if [[ ! -f "$BIN" ]]; then
	echo "binary not found: $BIN" >&2
	echo "build it first: go build -o mtufinder mtufinder.go" >&2
	exit 1
fi

case "$(uname -s)" in
	Linux)
		if command -v setcap >/dev/null 2>&1; then
			echo "granting cap_net_raw to $BIN (requires sudo)"
			sudo setcap cap_net_raw+ep "$BIN"
			echo "done. verify with: getcap $BIN"
		else
			echo "setcap not found, falling back to setuid root"
			sudo chown root:root "$BIN"
			sudo chmod 4755 "$BIN"
			echo "done. verify with: ls -l $BIN"
		fi
		;;
	Darwin)
		echo "setting setuid root on $BIN (requires sudo)"
		sudo chown root:wheel "$BIN"
		sudo chmod 4755 "$BIN"
		echo "done. verify with: ls -l $BIN"
		;;
	*)
		echo "unsupported OS: $(uname -s)" >&2
		echo "on Windows, run mtufinder.exe from an Administrator shell." >&2
		exit 2
		;;
esac
