package lock

import (
	"fmt"
	"sort"

	"github.com/Breaktroughf1/lockward/internal/asset"
)

// Status is a verification result (SPEC §6).
type Status string

// Statuses.
const (
	StatusOK       Status = "ok"
	StatusAdded    Status = "added"
	StatusRemoved  Status = "removed"
	StatusModified Status = "modified"
)

// Result compares one id across the lockfile and live state.
type Result struct {
	ID     string
	Status Status
	Locked *asset.Entry // nil when added
	Live   *asset.Entry // nil when removed
}

// Entry returns the live entry if present, else the locked one.
func (r Result) Entry() *asset.Entry {
	if r.Live != nil {
		return r.Live
	}
	return r.Locked
}

// Compare matches live entries against locked entries by id (SPEC §6). The
// result is sorted by id and contains one Result per id in either set.
func Compare(locked, live []asset.Entry) []Result {
	lockedByID := index(locked)
	liveByID := index(live)
	ids := make([]string, 0, len(lockedByID)+len(liveByID))
	for id := range lockedByID {
		ids = append(ids, id)
	}
	for id := range liveByID {
		if _, ok := lockedByID[id]; !ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	out := make([]Result, 0, len(ids))
	for _, id := range ids {
		l, inLock := lockedByID[id]
		v, inLive := liveByID[id]
		r := Result{ID: id, Locked: l, Live: v}
		switch {
		case !inLock:
			r.Status = StatusAdded
		case !inLive:
			r.Status = StatusRemoved
		case l.Digest != v.Digest || l.ToolsFingerprint != v.ToolsFingerprint:
			r.Status = StatusModified
		default:
			r.Status = StatusOK
		}
		out = append(out, r)
	}
	return out
}

func index(entries []asset.Entry) map[string]*asset.Entry {
	m := make(map[string]*asset.Entry, len(entries))
	for i := range entries {
		m[entries[i].ID] = &entries[i]
	}
	return m
}

// Counts tallies results by status.
func Counts(results []Result) map[Status]int {
	c := map[Status]int{}
	for _, r := range results {
		c[r.Status]++
	}
	return c
}

// Drift reports whether any result is not ok. With frozen false, only
// removed and modified entries count; additions are reported but tolerated
// (see PRD §8 and docs/USAGE.md).
func Drift(results []Result, frozen bool) bool {
	for _, r := range results {
		switch r.Status {
		case StatusModified, StatusRemoved:
			return true
		case StatusAdded:
			if frozen {
				return true
			}
		}
	}
	return false
}

// Relock builds the entries for a fresh lock from live state, carrying over
// each approval whose id and digest are unchanged.
func Relock(old, live []asset.Entry) []asset.Entry {
	oldByID := index(old)
	out := make([]asset.Entry, len(live))
	for i, e := range live {
		if o, ok := oldByID[e.ID]; ok && o.Digest == e.Digest && o.ToolsFingerprint == e.ToolsFingerprint {
			e.Approved = o.Approved
		}
		out[i] = e
	}
	SortEntries(out)
	return out
}

// Approve updates only the selected ids in locked from live state (LW-FR-10).
// An id present live is added or replaced and stamped with by; an id absent
// live is removed. If all is true every differing id is approved. Unknown ids
// are an error so a typo never silently approves nothing.
func Approve(locked, live []asset.Entry, ids []string, all bool, by string) ([]asset.Entry, []string, error) {
	results := Compare(locked, live)
	byID := make(map[string]Result, len(results))
	for _, r := range results {
		byID[r.ID] = r
	}
	selected := map[string]bool{}
	if all {
		for _, r := range results {
			if r.Status != StatusOK {
				selected[r.ID] = true
			}
		}
	}
	for _, id := range ids {
		if _, ok := byID[id]; !ok {
			return nil, nil, fmt.Errorf("unknown entry id %q (see 'lockward verify' for ids)", id)
		}
		selected[id] = true
	}
	out := make([]asset.Entry, 0, len(locked)+len(selected))
	var approved []string
	for _, r := range results {
		switch {
		case !selected[r.ID]:
			if r.Locked != nil {
				out = append(out, *r.Locked)
			}
		case r.Live != nil:
			e := *r.Live
			if by != "" {
				e.Approved = &asset.Approval{By: by}
			} else if r.Locked != nil && r.Status == StatusOK {
				e.Approved = r.Locked.Approved
			}
			out = append(out, e)
			approved = append(approved, r.ID)
		default: // selected and removed live: drop it
			approved = append(approved, r.ID)
		}
	}
	SortEntries(out)
	return out, approved, nil
}
