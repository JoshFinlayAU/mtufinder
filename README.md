# mtufinder

Small tool that binary-searches the path MTU to a target host using ICMP
echo with the Don't Fragment bit set. Single Go binary, no system `ping`
dependency, no external runtime.

I wrote this because every other "what's my path MTU" script I tried either
shelled out to `ping` (whose flags differ on every OS), needed Python on a
Windows box that didn't have it, or used some unmaintained pcap library.

## Build

```sh
go build -o mtufinder mtufinder.go
```

Go 1.22+ should be fine. Only external import is `golang.org/x/net`, which
gets compiled in.

Cross-compile if you want:

```sh
GOOS=linux   GOARCH=amd64 go build -o mtufinder-linux-amd64    mtufinder.go
GOOS=linux   GOARCH=arm64 go build -o mtufinder-linux-arm64    mtufinder.go
GOOS=darwin  GOARCH=amd64 go build -o mtufinder-darwin-amd64   mtufinder.go
GOOS=darwin  GOARCH=arm64 go build -o mtufinder-darwin-arm64   mtufinder.go
GOOS=windows GOARCH=amd64 go build -o mtufinder-windows-amd64.exe mtufinder.go
GOOS=windows GOARCH=arm64 go build -o mtufinder-windows-arm64.exe mtufinder.go
```

Or grab a prebuilt from the [releases page](../../releases). Debian/Ubuntu
users can install the `.deb` instead:

```sh
sudo dpkg -i mtufinder_<version>_<arch>.deb
```

The package's postinst applies `setcap cap_net_raw+ep` for you, so no sudo
needed at runtime.

## Usage

```sh
sudo ./mtufinder 8.8.8.8
sudo ./mtufinder one.one.one.one
sudo ./mtufinder --max 9000 --timeout 1500 192.0.2.1
```

Flags:

```
  -min int       minimum MTU to probe (default: 68 v4 / 1280 v6)
  -max int       maximum MTU to probe (default 9000)
  -timeout int   per-probe timeout in milliseconds (default 2000)
  -quiet         suppress progress output
  -json          emit machine-readable JSON instead of human output (implies -quiet)
```

JSON mode for scripts/pipelines — exit code still signals success/failure:

```sh
$ sudo ./mtufinder --json 8.8.8.8
{
  "success": true,
  "target": "8.8.8.8",
  "ip": "8.8.8.8",
  "family": 4,
  "mtu": 1500,
  "min": 68,
  "max": 9000,
  "timeout_ms": 2000,
  "elapsed_ms": 214
}
```

On failure the same shape comes back with `"success": false` and an `"error"`
field, so `jq` pipelines don't need a separate error path.

Sample output:

```
[*] Target:  8.8.8.8 -> 8.8.8.8 (IPv4)
[*] OS:      darwin
[*] Range:   68 - 9000 bytes
[*] Timeout: 2000 ms/probe

[*] Baseline reachability at MTU 68...
[*] Trying upper bound 9000...
    probe MTU=4534  -> TIMEOUT
    probe MTU=2301  -> TIMEOUT
    probe MTU=1184  -> OK
    ...
Path MTU to 8.8.8.8 (8.8.8.8): 1500 bytes
```

## Why it needs root

It opens a raw ICMP socket directly rather than shelling out to `ping`.
That gives us a consistent code path on every OS, but raw sockets are
privileged everywhere.

Options:

- **Linux**: grant the capability instead of running as root every time.
  ```sh
  sudo setcap cap_net_raw+ep ./mtufinder
  ```
- **macOS**: setuid root, or run with `sudo`.
  ```sh
  sudo chown root:wheel ./mtufinder && sudo chmod 4755 ./mtufinder
  ```
- **Windows**: run it from an elevated (Administrator) shell.

`install.sh` does the Linux/macOS bit for you:

```sh
go build -o mtufinder mtufinder.go
./install.sh
./mtufinder 1.1.1.1     # no sudo needed after this
```

## How it works

1. Open a raw ICMPv4 socket and wrap it with `ipv4.RawConn` so we control
   the IP header (and therefore the DF flag) ourselves. Avoids per-OS
   `setsockopt` constants.
2. Confirm baseline reachability at the minimum MTU. If that fails, bail
   early — no point searching.
3. Try the upper bound. If it works, we're done.
4. Otherwise binary-search between min and max. Treat `TIMEOUT` the same
   as `TOO_BIG`, because a broken PMTUD path (ICMP black hole) silently
   drops oversize probes rather than returning a Fragmentation Needed
   message.

IPv6 path: same idea, minus the DF bit. IPv6 routers don't fragment in
transit, so an oversize packet either elicits an ICMPv6 Packet Too Big or
times out.

## Caveats

- Some networks rate-limit or drop ICMP entirely. If even the baseline
  probe fails, the tool gives up rather than guessing.
- Result is the MTU between *you* and the target along the path active
  right now. Asymmetric routing, ECMP, or a failover can shift this.
- Jumbo-frame paths (>1500) are uncommon outside of datacenter fabrics
  and a handful of carrier links. If you don't expect them, leave `--max`
  alone.

## License

MIT.
