#!/usr/bin/env bash
set -uo pipefail
cd /tmp/soc-network-integration
soc_python=/home/geonug/kdt-linux/autonomous-soc-agent/.venv/bin/python
report_directory=/home/geonug/kdt-linux/ML/reports
pids=()
for shard in 0 1 2 3; do
    "$soc_python" -m pytest -q --durations=10 "@network_v4_shard_${shard}.txt" \
        --basetemp="/dev/shm/soc-network-v4-shard-${shard}" \
        > "${report_directory}/network_v4_pytest_shard_${shard}.log" 2>&1 &
    pids+=("$!")
done
status=0
: > "${report_directory}/network_v4_shard_status.txt"
for shard in 0 1 2 3; do
    code=0
    wait "${pids[$shard]}" || code=$?
    printf 'shard %s exit %s\n' "$shard" "$code" | tee -a "${report_directory}/network_v4_shard_status.txt"
    if [[ "$code" != 0 ]]; then status=1; fi
done
exit "$status"
