// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// Upper bound of ban and unban operations queued per target and request.
const maxSyncBans = 1000

// Omitted options default to true.
type syncRequest struct {
	Tags    []string `json:"tags"`
	Jails   *bool    `json:"jails"`
	Filters *bool    `json:"filters"`
	Bans    *bool    `json:"bans"`
	Unbans  *bool    `json:"unbans"`
}

type syncOptions struct{ Jails, Filters, Bans, Unbans bool }

func (r syncRequest) options() syncOptions {
	on := func(v *bool) bool { return v == nil || *v }
	return syncOptions{Jails: on(r.Jails), Filters: on(r.Filters), Bans: on(r.Bans), Unbans: on(r.Unbans)}
}

type plannedOperation struct {
	Kind string
	Jail string
	IP   string
	Body json.RawMessage
}

// A jail as one server sees it.
type jailSide struct {
	Exists    bool // defined in the configuration or active
	Active    bool
	Config    string
	Filter    string
	HasFilter bool
	Banned    []string
}

// A tag shared by a server and one of its jails makes that server the source
// for the jail; every other server carrying the tag is a target.
type syncGroup struct {
	Tag       string
	SourceID  string
	Jails     []string
	TargetIDs []string
	Err       string
}

func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

// Groups servers by tag. Only is optional; empty means every tag that marks a jail.
func buildSyncGroups(servers []shared.Fail2banServer, only []string) []syncGroup {
	wanted := map[string]bool{}
	for _, tag := range shared.NormalizeTags(only) {
		wanted[tag] = true
	}
	tags := map[string]bool{}
	for _, srv := range servers {
		for _, jailTags := range srv.JailTags {
			for _, tag := range jailTags {
				if len(wanted) == 0 || wanted[tag] {
					tags[tag] = true
				}
			}
		}
	}
	for tag := range wanted {
		tags[tag] = true
	}
	names := make([]string, 0, len(tags))
	for tag := range tags {
		names = append(names, tag)
	}
	sort.Strings(names)

	groups := make([]syncGroup, 0, len(names))
	for _, tag := range names {
		g := syncGroup{Tag: tag}
		var sources []string
		for _, srv := range servers {
			if !hasTag(srv.Tags, tag) {
				continue
			}
			var jails []string
			for jail, jailTags := range srv.JailTags {
				if hasTag(jailTags, tag) {
					jails = append(jails, jail)
				}
			}
			if len(jails) == 0 {
				g.TargetIDs = append(g.TargetIDs, srv.ID)
				continue
			}
			sort.Strings(jails)
			sources = append(sources, srv.ID)
			g.SourceID, g.Jails = srv.ID, jails
		}
		switch {
		case len(sources) == 0:
			g.Err = "No server tagged '" + tag + "' has a jail with this tag"
		case len(sources) > 1:
			g.Err = "Several servers have jails tagged '" + tag + "'; only one source is allowed"
		case len(g.TargetIDs) == 0:
			g.Err = "No other server is tagged '" + tag + "'"
		}
		groups = append(groups, g)
	}
	return groups
}

func ipSet(ips []string) map[string]bool {
	set := make(map[string]bool, len(ips))
	for _, ip := range ips {
		set[canonicalBanAddress(ip)] = true
	}
	return set
}

// Builds the operations that make one jail on the target match the source.
// Jails and filters are only added or overwritten; bans and unbans mirror the
// source. pendingBans counts bans that must wait until the jail is active on the target.
func planJail(name string, src, dst jailSide, opts syncOptions) (ops []plannedOperation, pendingBans int) {
	srcContent := fail2ban.NormalizeJailSection(name, src.Config)
	filterName := fail2ban.FilterNameForJail(name, src.Config)
	sendFilter := opts.Filters && src.HasFilter && fail2ban.ValidateFilterName(filterName) == nil
	created := false

	switch {
	case !dst.Exists && opts.Jails:
		req := jailCreateRequest{JailName: name, Content: srcContent}
		if sendFilter {
			req.Filter = src.Filter
		}
		body, _ := json.Marshal(req)
		ops = append(ops, plannedOperation{Kind: "jail.create", Jail: name, Body: body})
		created = true
	case dst.Exists:
		sameFilterName := fail2ban.FilterNameForJail(name, dst.Config) == filterName
		if opts.Jails && strings.TrimSpace(fail2ban.NormalizeJailSection(name, dst.Config)) != strings.TrimSpace(srcContent) {
			body, _ := json.Marshal(jailConfigRequest{Jail: srcContent})
			ops = append(ops, plannedOperation{Kind: "jail.config", Jail: name, Body: body})
			sameFilterName = true // applied first, so the filter op sees the new filter name
		} else if !opts.Jails && !sameFilterName {
			sendFilter = false
		}
		differs := !dst.HasFilter || strings.TrimSpace(dst.Filter) != strings.TrimSpace(src.Filter)
		if sendFilter && (!sameFilterName || differs) {
			body, _ := json.Marshal(jailConfigRequest{Filter: src.Filter})
			ops = append(ops, plannedOperation{Kind: "jail.config", Jail: name, Body: body})
		}
	}

	if !src.Active {
		return ops, 0
	}
	if created || !dst.Active {
		if opts.Bans && (created || dst.Exists) {
			pendingBans = len(src.Banned)
		}
		return ops, pendingBans
	}
	srcSet, dstSet := ipSet(src.Banned), ipSet(dst.Banned)
	if opts.Bans {
		for _, ip := range src.Banned {
			if !dstSet[canonicalBanAddress(ip)] && shared.ValidateIP(ip) == nil {
				ops = append(ops, plannedOperation{Kind: "jail.ban", Jail: name, IP: ip})
			}
		}
	}
	if opts.Unbans {
		for _, ip := range dst.Banned {
			if !srcSet[canonicalBanAddress(ip)] && shared.ValidateIP(ip) == nil {
				ops = append(ops, plannedOperation{Kind: "jail.unban", Jail: name, IP: ip})
			}
		}
	}
	return ops, 0
}

// Reads one jail from a server using a fresh snapshot.
func readJailSide(ctx context.Context, conn fail2ban.Connector, snap *ServerSnapshot, name string, withFiles bool) (jailSide, error) {
	side := jailSide{}
	for _, j := range snap.Configured {
		if j.JailName == name {
			side.Exists = true
		}
	}
	for _, j := range snap.Summary.Jails {
		if j.JailName == name {
			side.Exists, side.Active, side.Banned = true, true, j.BannedIPs
		}
	}
	if !side.Exists || !withFiles {
		return side, nil
	}
	content, _, err := conn.GetJailConfig(ctx, name)
	if err != nil {
		return side, fmt.Errorf("Cannot read jail '%s' on %s: %w", name, conn.Server().Name, err)
	}
	side.Config = content
	if filter, _, err := conn.GetFilterConfig(ctx, fail2ban.FilterNameForJail(name, content)); err == nil {
		side.Filter, side.HasFilter = filter, true
	}
	return side, nil
}

func freshSnapshot(ctx context.Context, conn fail2ban.Connector) (*ServerSnapshot, error) {
	readCtx, cancel := context.WithTimeout(ctx, snapshotReadTimeout)
	defer cancel()
	snap, err := RefreshServerSnapshot(readCtx, conn)
	if err != nil || snap == nil || snap.Summary == nil {
		return nil, fmt.Errorf("Cannot read the state of %s", conn.Server().Name)
	}
	return snap, nil
}

type syncTargetResult struct {
	ServerID    string   `json:"serverId"`
	Operations  []string `json:"operations"`
	PendingBans int      `json:"pendingBans,omitempty"`
	Skipped     int      `json:"skipped,omitempty"`
	Error       string   `json:"error,omitempty"`
}

type syncGroupResult struct {
	Tag     string             `json:"tag"`
	Source  string             `json:"source,omitempty"`
	Jails   []string           `json:"jails,omitempty"`
	Targets []syncTargetResult `json:"targets,omitempty"`
	Error   string             `json:"error,omitempty"`
}

// Syncs tagged jails (config, filter, bans and unbans) from their source server
// to the other servers with the same tag. Each change is queued as the regular
// per-server operation, so locking, validation, backup and rollback match
// manual edits.
func SyncTagsHandler(c *gin.Context) {
	if operationService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Background operations are not available"})
		return
	}
	var req syncRequest
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
			return
		}
	}
	opts := req.options()
	if !opts.Jails && !opts.Filters && !opts.Bans && !opts.Unbans {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Nothing selected to sync"})
		return
	}
	manager := fail2ban.GetManager()
	var servers []shared.Fail2banServer
	for _, conn := range manager.Connectors() {
		servers = append(servers, conn.Server())
	}
	groups := buildSyncGroups(servers, req.Tags)
	if len(groups) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No jail is tagged; add tags to a server and one of its jails first"})
		return
	}
	results := make([]syncGroupResult, 0, len(groups))
	for _, g := range groups {
		results = append(results, runSyncGroup(c.Request.Context(), manager, g, opts))
	}
	c.JSON(http.StatusAccepted, gin.H{"groups": results})
}

func runSyncGroup(ctx context.Context, manager *fail2ban.Manager, g syncGroup, opts syncOptions) syncGroupResult {
	res := syncGroupResult{Tag: g.Tag, Source: g.SourceID, Jails: g.Jails, Error: g.Err}
	if g.Err != "" {
		return res
	}
	source, err := manager.Connector(g.SourceID)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	srcSnap, err := freshSnapshot(ctx, source)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	sources := make(map[string]jailSide, len(g.Jails))
	for _, name := range g.Jails {
		side, err := readJailSide(ctx, source, srcSnap, name, true)
		if err == nil && !side.Exists {
			err = fmt.Errorf("Jail '%s' does not exist on %s", name, source.Server().Name)
		}
		if err != nil {
			res.Error = err.Error()
			return res
		}
		sources[name] = side
	}
	for _, id := range g.TargetIDs {
		res.Targets = append(res.Targets, syncTarget(ctx, manager, id, g.Jails, sources, opts))
	}
	return res
}

func syncTarget(ctx context.Context, manager *fail2ban.Manager, id string, jails []string, sources map[string]jailSide, opts syncOptions) syncTargetResult {
	res := syncTargetResult{ServerID: id, Operations: []string{}}
	conn, err := manager.Connector(id)
	if err == nil {
		var snap *ServerSnapshot
		if snap, err = freshSnapshot(ctx, conn); err == nil {
			var planned []plannedOperation
			for _, name := range jails {
				var dst jailSide
				if dst, err = readJailSide(ctx, conn, snap, name, opts.Jails || opts.Filters); err != nil {
					break
				}
				ops, pending := planJail(name, sources[name], dst, opts)
				planned = append(planned, ops...)
				res.PendingBans += pending
			}
			if err == nil {
				planned, res.Skipped = capBans(planned)
				res.Operations, err = submitPlanned(ctx, conn, planned)
			}
		}
	}
	if err != nil {
		res.Error = err.Error()
	}
	return res
}

// Keeps configuration changes and at most maxSyncBans ban/unban operations.
func capBans(planned []plannedOperation) ([]plannedOperation, int) {
	kept, bans, skipped := planned[:0:0], 0, 0
	for _, op := range planned {
		if op.Kind == "jail.ban" || op.Kind == "jail.unban" {
			if bans++; bans > maxSyncBans {
				skipped++
				continue
			}
		}
		kept = append(kept, op)
	}
	return kept, skipped
}

func submitPlanned(ctx context.Context, conn fail2ban.Connector, planned []plannedOperation) ([]string, error) {
	ids := []string{}
	fingerprint := serverFingerprint(conn.Server())
	for _, op := range planned {
		payload := operationPayload{Fingerprint: fingerprint, Jail: op.Jail, IP: op.IP, Body: op.Body}
		target, err := validateOperationPayload(op.Kind, payload)
		if err != nil {
			return ids, fmt.Errorf("%s: %w", op.Jail, err)
		}
		encoded, _ := json.Marshal(payload)
		queued, err := operationService.engine.Submit(ctx, conn.Server().ID, op.Kind, target, "", encoded)
		if err != nil {
			return ids, errors.New("Cannot queue " + op.Kind + " for " + op.Jail + ": " + err.Error())
		}
		ids = append(ids, queued.ID)
	}
	return ids, nil
}
