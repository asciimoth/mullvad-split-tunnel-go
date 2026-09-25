#!/usr/bin/env bash
# Remote PowerShell paths intentionally expand on the client.
# shellcheck disable=SC2029,SC2054
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=dev/winvm/common.sh
source "$script_dir/common.sh"
mode=${1:-baseline}; shell_path=''
case $mode in baseline|e2e) ;; --shell) mode=shell; shell_path=${2:?usage: run.sh --shell RUN};; --clean) mode=clean;; *) die "unknown mode: $mode";; esac
artifact_root=$(realpath -m "$repo_root/$(jq -r .artifacts.directory "$config_file")")
[[ $artifact_root == "$repo_root/.artifacts/winvm" ]] || die "unsafe artifact root: $artifact_root"
if [[ $mode == clean ]]; then
    [[ -d $artifact_root ]] || { printf 'No Windows VM artifacts exist.\n'; exit; }
    ensure_cache_dir; mkdir -p "$winvm_cache_dir/locks"; exec 6>"$winvm_cache_dir/locks/vm-run.lock"
    flock -w 1800 6 || die 'an active VM held the host lock for 30 minutes'
    reject_live_qemu_orphan
    while IFS= read -r -d '' path; do resolved=$(realpath -e "$path"); [[ $resolved == "$artifact_root"/run-* ]] || die "unsafe cleanup target: $resolved"; find "$resolved" -depth -delete; done < <(find "$artifact_root" -mindepth 1 -maxdepth 1 -type d -name 'run-*' -print0)
    printf 'Removed validated VM runs. The base image was kept.\n'; exit
fi
for command in qemu-system-x86_64 qemu-img ssh scp jq python3 timeout flock git tar; do require_command "$command"; done
[[ -r /dev/kvm && -w /dev/kvm ]] || die '/dev/kvm is not accessible; run just winvm-doctor'
ensure_cache_dir; mkdir -p "$artifact_root" "$winvm_cache_dir/locks"; chmod 0700 "$artifact_root"
# One active VM per host prevents memory and CPU oversubscription from making
# boot and driver timing nondeterministic. The bounded flock also avoids hangs.
exec 6>"$winvm_cache_dir/locks/vm-run.lock"
flock -w 1800 6 || die 'another VM run held the host lock for 30 minutes'
reject_live_qemu_orphan
if [[ $mode == shell ]]; then run_dir=$(realpath -e "$shell_path"); [[ $run_dir == "$artifact_root"/run-* ]] || die 'retained run is outside artifact root'; key=$(jq -er .baseImageKey "$run_dir/run.json"); else key=$(base_key); fi
image_dir="$winvm_cache_dir/images/$key"; base="$image_dir/base.qcow2"; vars_base="$image_dir/OVMF_VARS.fd"; manifest="$image_dir/manifest.json"; host_key="$image_dir/host-key.pub"; ssh_key=$(ssh_private_key)
exec 8>"$winvm_cache_dir/locks/image-$key.lock"; flock -s 8
for path in "$base" "$vars_base" "$manifest" "$host_key" "$ssh_key"; do [[ -r $path ]] || die "base-image input is absent: $path; run just winvm-image"; done
[[ $(jq -r .baseImageKey "$manifest") == "$key" ]] || die 'base-image manifest key mismatch'
if [[ $mode != shell ]]; then
    allocated=0
    for _ in {1..20}; do run_id="run-$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM"; run_dir="$artifact_root/$run_id"; if mkdir -m 0700 "$run_dir" 2>/dev/null; then allocated=1; break; fi; done
    ((allocated)) || die 'cannot allocate a unique run directory'
fi
exec 5>"$run_dir/run.lock"; flock -n 5 || die 'this run is already active'
overlay="$run_dir/overlay.qcow2"; vars="$run_dir/OVMF_VARS.fd"; sockets=$(make_socket_dir); qga="$sockets/qga.sock"; qmp="$sockets/qmp.sock"; pid=''; success=0; stage=setup; test_status=1
safe_remove() {
    [[ $overlay == "$artifact_root"/run-*/overlay.qcow2 ]] || die "unsafe overlay: $overlay"
    if [[ -e $overlay ]]; then
        backing=$(qemu-img info --output=json "$overlay" | jq -r '."full-backing-filename" // ."backing-filename" // empty')
        [[ -n $backing && $(realpath -e "$backing") == "$(realpath -e "$base")" ]] || die 'refusing overlay with unexpected backing file'
        find "$overlay" -maxdepth 0 -type f -delete
    fi
}
stop_vm() {
    [[ -n $pid ]] || return 0
    if kill -0 "$pid" 2>/dev/null; then
        "$script_dir/tools/qga.py" --socket "$qga" --timeout 5 shutdown >>"$run_dir/guest-agent.log" 2>&1 || true
        wait_for_pid "$pid" "$(jq -r .machine.shutdownTimeoutSeconds "$config_file")" || "$script_dir/tools/qga.py" --socket "$qmp" --timeout 5 qmp quit >>"$run_dir/guest-agent.log" 2>&1 || true
        if ! stop_and_reap_pid "$pid" 10 10 10; then
            record_qemu_orphan "$pid"
            return 1
        fi
    else
        wait "$pid" 2>/dev/null || true
    fi
    pid=''
}
cleanup() {
    status=$?; trap - EXIT INT TERM; vm_stopped=1
    if ((status != 0)) && [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null && [[ -S $qga ]]; then
        diagnostics='Get-Process | Sort-Object ProcessName | Format-Table -AutoSize; Get-Service | Where-Object Name -Match "mullvad|qemu|ssh" | Format-Table -AutoSize; Get-WinEvent -FilterHashtable @{LogName="Application","System"; StartTime=(Get-Date).AddMinutes(-30)} -ErrorAction SilentlyContinue | Select-Object -First 100 | Format-List'
        "$script_dir/tools/qga.py" --socket "$qga" --timeout 30 exec powershell.exe -NoProfile -Command "$diagnostics" >"$run_dir/diagnostics.log" 2>&1 || true
        if [[ -n ${remote:-} ]]; then
            guest_remote=${remote//\//\\}
            "$script_dir/tools/qga.py" --socket "$qga" --timeout 30 exec tar.exe -cf "$guest_remote\\artifacts.tar" -C "$guest_remote" artifacts >/dev/null 2>&1 || true
            "$script_dir/tools/qga.py" --socket "$qga" --timeout 30 read "$guest_remote\\artifacts.tar" --limit 67108864 >"$run_dir/guest-artifacts.tar" 2>/dev/null || true
        fi
    fi
    if ! stop_vm; then
        vm_stopped=0; status=1; stage=cleanup-qemu
        printf 'winvm: QEMU survived cleanup; retaining VM disks and sockets\n' >&2
    fi
    if ((vm_stopped)); then remove_socket_dir "$sockets"; fi
    if [[ $mode != shell && -f $run_dir/run.json ]]; then
        if jq --argjson exit "$status" --arg stage "$stage" --arg finished "$(date -u +%FT%TZ)" '.exitStatus=$exit|.status=(if $exit==0 then "passed" else "failed" end)|.stage=$stage|.finishedAt=$finished' "$run_dir/run.json" >"$run_dir/run.json.new"; then
            mv "$run_dir/run.json.new" "$run_dir/run.json"
        fi
    fi
    if ((success && vm_stopped)); then safe_remove; find "$vars" -maxdepth 0 -type f -delete; elif [[ $mode != shell ]]; then printf '%s\n' "$stage" >"$run_dir/failure-stage.txt"; if ((vm_stopped)) && [[ $(jq -r .artifacts.retainFailedOverlay "$config_file") != true ]]; then safe_remove; else printf 'Retained failed overlay. Diagnose with: just winvm-shell %q\n' "$run_dir" >&2; fi; fi
    exit "$status"
}
trap cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM
if [[ $mode != shell ]]; then
    revision=$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf unknown); dirty=false; [[ -n $(git -C "$repo_root" status --porcelain) ]] && dirty=true
    jq -n --arg revision "$revision" --argjson dirty "$dirty" --arg key "$key" --arg mode "$mode" --arg started "$(date -u +%FT%TZ)" --arg testHash "$(sha256_file "$script_dir/test.ps1")" --arg e2eHash "$(sha256_file "$script_dir/e2e.ps1")" --arg runnerHash "$(sha256_file "$script_dir/run.sh")" '{revision:$revision,dirty:$dirty,baseImageKey:$key,mode:$mode,startedAt:$started,status:"running",stage:"setup",scriptHashes:{test:$testHash,e2e:$e2eHash,runner:$runnerHash}}' >"$run_dir/run.json"
    cp "$manifest" "$run_dir/image-manifest.json"; qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$overlay"
fi
actual=$(qemu-img info --output=json "$overlay" | jq -r '."full-backing-filename" // ."backing-filename" // empty'); [[ -n $actual && $(realpath -e "$actual") == "$(realpath -e "$base")" ]] || die 'overlay backing file mismatch'
if [[ $mode == shell ]]; then
    [[ -r $vars ]] || die 'retained OVMF variable store is absent'
else
    cp "$vars_base" "$vars"; chmod 0600 "$vars"
fi
allocate_locked_port; port=$winvm_ssh_port
read -r key_type key_data <"$host_key"; printf '[127.0.0.1]:%s %s %s\n' "$port" "$key_type" "$key_data" >"$run_dir/known_hosts"
qemu=(qemu-system-x86_64 -name "split-winvm-$mode" -machine "$(jq -r .machine.type "$config_file")" -cpu host -smp "$(jq -r .machine.cpus "$config_file")" -m "$(jq -r .machine.memoryMiB "$config_file")" -no-reboot -display none -chardev "file,id=serial0,path=$run_dir/serial.log" -serial chardev:serial0 -drive "if=pflash,format=raw,readonly=on,file=$(find_ovmf code)" -drive "if=pflash,format=raw,file=$vars" -device ich9-ahci,id=sata -drive "if=none,id=osdisk,format=qcow2,file=$overlay,cache=writeback" -device ide-hd,drive=osdisk,bus=sata.0 -device e1000e,netdev=net0 -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22" -device virtio-serial-pci -chardev "socket,path=$qga,server=on,wait=off,id=qga0" -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 -qmp "unix:$qmp,server=on,wait=off")
printf '%q ' "${qemu[@]}" >"$run_dir/qemu-command.log"; "${qemu[@]}" >>"$run_dir/qemu.log" 2>&1 & pid=$!
ssh_opts=(-i "$ssh_key" -p "$port" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$run_dir/known_hosts" -o ConnectTimeout=5); scp_opts=(-i "$ssh_key" -P "$port" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$run_dir/known_hosts" -o ConnectTimeout=5); target=winvm@127.0.0.1
stage=boot; boot_started=$SECONDS; deadline=$((SECONDS+$(jq -r .machine.bootTimeoutSeconds "$config_file"))); next_progress=$((SECONDS+30)); qga_ok=0; ssh_ok=0; ready_token=''
printf 'Starting the disposable Windows %s guest. Logs: %s\n' "$mode" "$run_dir"
while ((SECONDS<deadline)); do
    kill -0 "$pid" 2>/dev/null || die 'QEMU exited during boot'
    if ((qga_ok==0)) && "$script_dir/tools/qga.py" --socket "$qga" --timeout 5 ping >>"$run_dir/guest-agent.log" 2>&1; then ready_token=$("$script_dir/tools/qga.py" --socket "$qga" --timeout 10 exec powershell.exe -NoProfile -Command 'if(Test-Path C:\winvm\ready){Get-Content -Raw C:\winvm\ready}else{exit 1}' 2>/dev/null || true); [[ -n $ready_token ]] && qga_ok=1; fi
    if ((ssh_ok==0)) && ssh "${ssh_opts[@]}" "$target" 'powershell.exe -NoProfile -Command "if(Test-Path C:\winvm\ready){exit 0}else{exit 1}"' >/dev/null 2>&1; then ssh_ok=1; fi
    ((qga_ok && ssh_ok)) && break; sleep 2
    if ((SECONDS>=next_progress)); then printf 'Still booting Windows: %d seconds elapsed.\n' "$((SECONDS-boot_started))"; next_progress=$((SECONDS+30)); fi
done
((qga_ok && ssh_ok)) || die 'guest readiness timeout'
sleep 2; stable=$("$script_dir/tools/qga.py" --socket "$qga" --timeout 10 exec powershell.exe -NoProfile -Command 'Get-Content -Raw C:\winvm\ready'); [[ $stable == "$ready_token" ]] || die 'guest restarted across readiness check'
printf 'Windows guest is ready. Packaging and transferring the source tree...\n'
if [[ $mode == shell ]]; then stage=shell; ssh "${ssh_opts[@]}" -t "$target" powershell.exe; exit; fi
stage=package; payload="$run_dir/worktree.tar"; "$script_dir/package-worktree.sh" "$payload"; remote="C:/winvm/runs/${run_id//[^A-Za-z0-9-]/}"
payload_hash=$(sha256_file "$payload")
jq --arg hash "$payload_hash" '.sourceArchive={file:"worktree.tar",sha256:$hash}' "$run_dir/run.json" >"$run_dir/run.json.new"
mv "$run_dir/run.json.new" "$run_dir/run.json"
stage=transfer; ssh "${ssh_opts[@]}" "$target" "powershell.exe -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '$remote/source','$remote/artifacts'|Out-Null\""; scp "${scp_opts[@]}" "$payload" "$target:$remote/worktree.tar" >/dev/null; ssh "${ssh_opts[@]}" "$target" "tar.exe -xf \"$remote/worktree.tar\" -C \"$remote/source\""
stage='test'; test_timeout=$(jq -r .machine.testTimeoutSeconds "$config_file"); set +e
printf 'Running the Windows %s gate with a %d-minute timeout...\n' "$mode" "$((test_timeout/60))"
if [[ $mode == baseline ]]; then
    command="Set-Location '$remote/source'; & './dev/winvm/test.ps1' -ArtifactDir '$remote/artifacts' -ImageManifest 'C:/winvm/manifest.json' -RequireStandardUser"
    timeout --foreground --kill-after=30 "${test_timeout}s" ssh "${ssh_opts[@]}" "$target" "powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command \"$command\"" 2>&1 | tee "$run_dir/windows-console.log"; test_status=${PIPESTATUS[0]}
else
    command="& '$remote/source/dev/winvm/e2e.ps1' -SourceDir '$remote/source' -ArtifactDir '$remote/artifacts'"
    timeout --foreground --kill-after=30 "${test_timeout}s" "$script_dir/tools/qga.py" --socket "$qga" --timeout "$test_timeout" exec powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$command" 2>&1 | tee "$run_dir/windows-console.log"; test_status=${PIPESTATUS[0]}
fi
set -e; ((test_status==0)) || { ((test_status==124)) && stage=test-timeout; exit "$test_status"; }
stage=artifacts; artifact="$run_dir/guest-artifacts.tar"
if ssh "${ssh_opts[@]}" "$target" "tar.exe -cf \"$remote/artifacts.tar\" -C \"$remote\" artifacts" >/dev/null 2>&1 && scp "${scp_opts[@]}" "$target:$remote/artifacts.tar" "$artifact" >/dev/null 2>&1; then
    :
else
    guest_remote=${remote//\//\\}
    "$script_dir/tools/qga.py" --socket "$qga" --timeout 30 exec tar.exe -cf "$guest_remote\\artifacts.tar" -C "$guest_remote" artifacts >/dev/null
    "$script_dir/tools/qga.py" --socket "$qga" --timeout 30 read "$guest_remote\\artifacts.tar" --limit 67108864 >"$artifact"
fi
[[ -s $artifact ]] || die 'guest artifact archive is empty'
stage=shutdown; success=1; printf 'Windows %s gate passed. Artifacts: %s\n' "$mode" "$run_dir"
