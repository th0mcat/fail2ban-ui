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
	"encoding/json"
	"reflect"
	"testing"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

func kinds(ops []plannedOperation) []string {
	var out []string
	for _, op := range ops {
		out = append(out, op.Kind+":"+op.Jail+":"+op.IP)
	}
	return out
}

func TestBuildSyncGroups(t *testing.T) {
	servers := []shared.Fail2banServer{
		{ID: "s1", Tags: []string{"Jail1"}, JailTags: map[string][]string{"Jail1": {"Jail1"}}},
		{ID: "s3", Tags: []string{"Jail1", "Jail4"}},
		{ID: "s4", Tags: []string{"Jail4"}, JailTags: map[string][]string{"jail4": {"Jail4"}}},
		{ID: "s5", Tags: []string{"Jail1", "Jail4"}},
	}
	groups := buildSyncGroups(servers, nil)
	want := []syncGroup{
		{Tag: "Jail1", SourceID: "s1", Jails: []string{"Jail1"}, TargetIDs: []string{"s3", "s5"}},
		{Tag: "Jail4", SourceID: "s4", Jails: []string{"jail4"}, TargetIDs: []string{"s3", "s5"}},
	}
	if !reflect.DeepEqual(groups, want) {
		t.Fatalf("groups=%+v", groups)
	}

	servers[3].JailTags = map[string][]string{"x": {"Jail1"}}
	if g := buildSyncGroups(servers, []string{"Jail1"}); len(g) != 1 || g[0].Err == "" {
		t.Fatalf("two sources must be rejected: %+v", g)
	}
	if g := buildSyncGroups(servers, []string{"missing"}); len(g) != 1 || g[0].Err == "" {
		t.Fatalf("unknown tag must report an error: %+v", g)
	}
}

func TestPlanJailCreatesWithFilterAndDefersBans(t *testing.T) {
	src := jailSide{Exists: true, Active: true, Config: "[web]\nenabled = true\nfilter = web\n", Filter: "[Definition]\n", HasFilter: true, Banned: []string{"192.0.2.1"}}
	ops, pending := planJail("web", src, jailSide{}, syncOptions{true, true, true, true})
	if got := kinds(ops); !reflect.DeepEqual(got, []string{"jail.create:web:"}) || pending != 1 {
		t.Fatalf("ops=%v pending=%d", got, pending)
	}
	var req jailCreateRequest
	_ = json.Unmarshal(ops[0].Body, &req)
	if req.Filter != src.Filter {
		t.Fatalf("filter not sent with the new jail: %+v", req)
	}
}

func TestPlanJailMirrorsBansAndIsIdempotent(t *testing.T) {
	src := jailSide{Exists: true, Active: true, Config: "[sshd]\nenabled = true\n", Filter: "f", HasFilter: true, Banned: []string{"192.0.2.1", "192.0.2.2"}}
	dst := jailSide{Exists: true, Active: true, Config: "[sshd]\nenabled = true\n", Filter: "f", HasFilter: true, Banned: []string{"192.0.2.1", "198.51.100.9"}}
	ops, _ := planJail("sshd", src, dst, syncOptions{true, true, true, true})
	if got, want := kinds(ops), []string{"jail.ban:sshd:192.0.2.2", "jail.unban:sshd:198.51.100.9"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ops=%v", got)
	}
	if ops, _ := planJail("sshd", src, dst, syncOptions{Jails: true, Filters: true}); len(ops) != 0 {
		t.Fatalf("identical jail and filter must not be rewritten: %v", kinds(ops))
	}
	if ops, _ := planJail("sshd", src, dst, syncOptions{Bans: true}); len(ops) != 1 {
		t.Fatalf("bans only: %v", kinds(ops))
	}
}

func TestPlanJailUpdatesChangedFilterSeparately(t *testing.T) {
	src := jailSide{Exists: true, Config: "[a]\nfilter = new\n", Filter: "new-body", HasFilter: true}
	dst := jailSide{Exists: true, Config: "[a]\nfilter = old\n", Filter: "old-body", HasFilter: true}
	ops, _ := planJail("a", src, dst, syncOptions{Jails: true, Filters: true})
	if got, want := kinds(ops), []string{"jail.config:a:", "jail.config:a:"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ops=%v", got)
	}
}
