#!/bin/sh
# Run the go-ethereum v1.17.10 discv5 conformance suite against the test node
# of one target, then check that the node closes its socket.
# Usage: tests/conformance/run.sh DEVP2P NODE LISTEN2 [WRAPPER]
#   DEVP2P   the devp2p tool of go-ethereum v1.17.10 (build-devp2p.sh builds it)
#   NODE     the test node of the target: build/<os>-<isa>/node or node.exe
#   LISTEN2  the second tester address: 127.0.0.2 where the loopback takes it,
#            else 127.0.0.1 (sessions are per address and port, so a second
#            port on the same address still counts as another endpoint)
#   WRAPPER  how to run the node, such as qemu-riscv64; empty to run it as is
# Prints the suite output, then "FUNCTION <name> PASS" for each shell function
# when every test passed and the node closed its socket.
set -eu
devp2p=$1
node=$2
listen2=$3
wrapper=${4:-}
log=$(mktemp)
$wrapper "$node" 127.0.0.1 30399 >"$log" 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true; rm -f "$log"' EXIT
enr=""
for _ in $(seq 1 200); do
    enr=$(sed -n '1{/^enr:/p;}' "$log")
    [ -n "$enr" ] && break
    sleep 0.1
done
if [ -z "$enr" ]; then
    echo "conformance: the node printed no record" >&2
    cat "$log" >&2
    exit 1
fi
status=0
"$devp2p" discv5 test --listen1 127.0.0.1 --listen2 "$listen2" "$enr" || status=1
kill $pid 2>/dev/null || true

# A second node closes its socket after 1 second.
$wrapper "$node" 127.0.0.1 30398 -x 1 >"$log" 2>&1 || status=1
grep -q '^closed$' "$log" || { echo "conformance: the node did not close its socket" >&2; status=1; }

if [ $status -eq 0 ]; then
    for f in discv5_shell_open discv5_shell_clock discv5_shell_send discv5_shell_receive discv5_shell_close; do
        echo "FUNCTION $f PASS"
    done
fi
exit $status
