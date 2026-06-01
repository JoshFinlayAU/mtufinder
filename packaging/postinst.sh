#!/bin/sh
set -e

# grant CAP_NET_RAW so users can run mtufinder without sudo.
# libcap2-bin (which provides setcap) is a declared dependency.
if command -v setcap >/dev/null 2>&1; then
	setcap cap_net_raw+ep /usr/bin/mtufinder || true
fi
