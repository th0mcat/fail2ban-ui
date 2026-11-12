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

package shared

import "strings"

// Trims tags, drops empty ones and removes duplicates, keeping the first-seen order.
func NormalizeTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	seen := make(map[string]bool, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		out = append(out, tag)
	}
	return out
}

// Normalizes every jail's tags and drops jails left without tags.
func NormalizeJailTags(jailTags map[string][]string) map[string][]string {
	out := make(map[string][]string, len(jailTags))
	for jail, tags := range jailTags {
		jail = strings.TrimSpace(jail)
		if tags = NormalizeTags(tags); jail != "" && len(tags) > 0 {
			out[jail] = tags
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
