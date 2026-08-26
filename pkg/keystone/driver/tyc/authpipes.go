// Copyright 2026 Yunion
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tyc

import (
	"context"
	"encoding/json"
	"strings"

	"yunion.io/x/log"

	"yunion.io/x/onecloud/pkg/util/rbacutils"
)

// 管道 A：动作权限直接控制（不经过角色）。
//
// 设计原则：
//   - BuildVirtualPolicyRules 根据 TycScope 直接构造策略规则（[]SRbacRule）
//   - AllowWithTycScope 在原生 PolicyManager 拒绝后检查虚拟规则
//   - 对"非 TYC 用户"完全 0 行为差异（scope == nil 时不生效）

// AllActions 所有可能的动作
var AllActions = []string{"list", "get", "create", "update", "delete", "perform"}

// BuildVirtualPolicyRules 把 TycScope 直接翻译成虚拟策略规则。
// 返回的 []SRbacRule 用于 AllowWithTycScope 评估。
func BuildVirtualPolicyRules(scope *TycScope) []rbacutils.SRbacRule {
	if scope == nil {
		return nil
	}

	allowActions := ActionsForLevel(scope.ActionLevel)
	allowSet := make(map[string]struct{}, len(allowActions))
	for _, a := range allowActions {
		allowSet[a] = struct{}{}
	}

	var rules []rbacutils.SRbacRule

	// 1) 通配规则（service=* resource=* 对所有资源生效）
	for _, action := range AllActions {
		result := rbacutils.Deny
		if _, ok := allowSet[action]; ok {
			result = rbacutils.Allow
		}
		rules = append(rules, rbacutils.SRbacRule{
			Service:  "*",
			Resource: "*",
			Action:   action,
			Result:   result,
		})
	}

	// 2) ActionOverrides（705 接口逐资源精确覆盖，优先级高于通配）
	for _, ov := range scope.ActionOverrides {
		for _, action := range ov.Allow {
			rules = append(rules, rbacutils.SRbacRule{
				Service:  ov.Service,
				Resource: ov.Resource,
				Action:   action,
				Result:   rbacutils.Allow,
			})
		}
		for _, action := range ov.Deny {
			rules = append(rules, rbacutils.SRbacRule{
				Service:  ov.Service,
				Resource: ov.Resource,
				Action:   action,
				Result:   rbacutils.Deny,
			})
		}
	}

	return rules
}

// AllowWithTycScope 检查 TycScope 虚拟规则是否允许指定动作。
// 返回 nil 表示 TycScope 无裁决（非 TYC 用户或无匹配规则）。
func AllowWithTycScope(ctx context.Context, service, resource, action string) *rbacutils.TRbacResult {
	tycScope := GetTycScope(ctx)
	if tycScope == nil {
		return nil
	}
	rules := BuildVirtualPolicyRules(tycScope)
	return MatchRules(rules, service, resource, action)
}

// MatchRules 按规则优先级匹配：精确资源 > 通配资源；Deny 覆盖中精确 Deny 优先
func MatchRules(rules []rbacutils.SRbacRule, service, resource, action string) *rbacutils.TRbacResult {
	var wildcardResult *rbacutils.TRbacResult
	for i := range rules {
		r := &rules[i]
		if !ruleFieldMatch(r.Service, service) {
			continue
		}
		if !ruleFieldMatch(r.Resource, resource) {
			continue
		}
		if !ruleFieldMatch(r.Action, action) {
			continue
		}
		if r.Service == "*" || r.Resource == "*" {
			result := r.Result
			wildcardResult = &result
		} else {
			result := r.Result
			return &result
		}
	}
	return wildcardResult
}

func ruleFieldMatch(pattern, value string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	return strings.EqualFold(pattern, value)
}

// LoadScopeFromJSON 从 JSON 字符串反解 TycScope（供请求中间件使用）
func LoadScopeFromJSON(scopeJSON string) *TycScope {
	if len(scopeJSON) == 0 {
		return nil
	}
	scope := &TycScope{}
	if err := json.Unmarshal([]byte(scopeJSON), scope); err != nil {
		log.Warningf("tyc LoadScopeFromJSON: unmarshal fail: %v", err)
		return nil
	}
	return scope
}

// ── ctx 注入 helper ──────────────────────────────────────────────────────

type tycScopeKey struct{}

func WithTycScope(ctx context.Context, s *TycScope) context.Context {
	return context.WithValue(ctx, tycScopeKey{}, s)
}

func GetTycScope(ctx context.Context) *TycScope {
	v, _ := ctx.Value(tycScopeKey{}).(*TycScope)
	return v
}

// TycScopeTTLExpired 检查 ScopeSnapshot 是否过期（返回 true = 需要异步刷新）
func TycScopeTTLExpired(s *TycScope, nowUnix, ttlSeconds int64) bool {
	if s == nil {
		return false
	}
	if ttlSeconds <= 0 {
		ttlSeconds = 60
	}
	if s.SnapshotAt <= 0 {
		return true
	}
	return nowUnix-s.SnapshotAt > ttlSeconds
}
