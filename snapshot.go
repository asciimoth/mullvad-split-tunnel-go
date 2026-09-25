package splittunnel

import "sort"

// normalizeSnapshot preserves input ownership and excludes unverified ancestry.
func normalizeSnapshot(processes []Process) []Process {
	out := append([]Process(nil), processes...)
	byPID := make(map[uint32]Process, len(out))
	for _, p := range out {
		byPID[p.PID] = p
	}
	for i, p := range out {
		parent, found := byPID[p.ParentPID]
		if p.ParentPID == p.PID || !found || p.CreationTime == 0 ||
			parent.CreationTime == 0 || parent.CreationTime > p.CreationTime {
			out[i].ParentPID = 0
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}
