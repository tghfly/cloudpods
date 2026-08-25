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
	"fmt"
	"sort"

	"yunion.io/x/log"
	"yunion.io/x/pkg/errors"

	models "yunion.io/x/onecloud/pkg/keystone/models"
)

// 管道 A + 管道 B 的 wrapper 层。
//
// 设计原则：
//   * pipeline A（ScopeResolver）只替换 PolicyManager 调用方的"取用户在项目上角色"那一处入口（wrapper），
//     完全不改 policy.go / rbac.go 内部；
//   * pipeline B（TagFilter）在【原生 policy.ApplyPolicyFilter 之后】"追加"行过滤条件，不改原过滤链；
//   * 两者都对"非 TYC 用户"完全 0 行为差异（scope == nil 时返回原值）。
//
// 注意：这里的 models / policy 调用接口是与项目约定的命名。落地时按真实方法名改，逻辑不变。

// Assignment 最小抽象。真实落地替换成 models.SAssignment 类型即可。
type Assignment struct {
	ProjectId string
	RoleId    string
	// Extra 预留：如果将来要区分 src=tyc（virtual） vs src=manual（real），这里加 tag
}

// ── 管道 A：ScopeResolver.BuildVirtualAssignments ───────────────────────────

// BuildVirtualAssignments 把 TycScope → 虚拟 assignments（不落库；每次鉴权派生前调用）。
// idx 给 ORG_SUBTREE 用：取该组织子树里所有"业务项目集合"（查 ProjectTags['org'] 祖先链）。
// 对单项目的角色数量 ≤ MaxUserRolesInProject(5)；超出时去重并告警。
func BuildVirtualAssignments(ctx context.Context, scope *TycScope, idx *OrgTreeIndex, maxRolesPerProj int) ([]Assignment, error) {
	if scope == nil {
		return nil, nil
	}
	roleId := scope.CloudRoleId
	if len(roleId) == 0 {
		roleId = MapTycRoleToPredefined(scope.DistrictAdm, scope.TycRoleName) // 兜底
	}
	var out []Assignment

	switch scope.DataScope.Level {
	case DataScopeDomainAll:
		// 在"域根 ORG-O000 项目"上挂一个角色：AllowScope 逐级回溯能推导到 ScopeDomain
		if idx != nil && len(idx.DomainRootOrgProjectId) > 0 {
			out = append(out, Assignment{ProjectId: idx.DomainRootOrgProjectId, RoleId: roleId})
		}

	case DataScopeOrgSubtree:
		orgId := scope.DataScope.OrgId
		if idx == nil || len(orgId) == 0 {
			return nil, fmt.Errorf("ORG_SUBTREE scope missing orgId/index")
		}
		projIds, err := idx.ListBusinessProjectIdsUnderOrg(ctx, orgId)
		if err != nil {
			return nil, errors.Wrapf(err, "list business projects under org %s", orgId)
		}
		for _, pid := range projIds {
			out = append(out, Assignment{ProjectId: pid, RoleId: roleId})
		}

	case DataScopeProjectSet:
		for _, pid := range scope.DataScope.ProjectIds {
			if len(pid) == 0 {
				continue
			}
			out = append(out, Assignment{ProjectId: pid, RoleId: roleId})
		}

	case DataScopeMixed:
		seen := map[string]struct{}{}
		appendOnce := func(pid, rid string) {
			key := pid + "\x00" + rid
			if _, ok := seen[key]; ok {
				return
			}
			seen[key] = struct{}{}
			out = append(out, Assignment{ProjectId: pid, RoleId: rid})
		}
		// 1) 多组织子树
		orgs := scope.DataScope.OrgIds
		if len(scope.DataScope.OrgId) > 0 {
			orgs = append([]string{scope.DataScope.OrgId}, orgs...)
		}
		for _, oid := range orgs {
			if idx == nil {
				continue
			}
			projIds, err := idx.ListBusinessProjectIdsUnderOrg(ctx, oid)
			if err != nil {
				return nil, errors.Wrapf(err, "mixed: list projects under org %s", oid)
			}
			for _, pid := range projIds {
				appendOnce(pid, roleId)
			}
		}
		// 2) 显式项目集合
		for _, pid := range scope.DataScope.ProjectIds {
			appendOnce(pid, roleId)
		}

	default:
		return nil, fmt.Errorf("unknown TycScope DataScope.Level=%s", scope.DataScope.Level)
	}
	return DedupeAndCapAssignments(out, maxRolesPerProj), nil
}

// DedupeAndCapAssignments 去重（按 projectId+roleId）+ 单项目上限。
// 优先级：若同一项目里有高/低角色（未来多角色叠加），先保留 roleId 高优先级（domainadmin > owner > editor > viewer > member）。
// 由于 v2 默认一项目只挂 1 个，这里的 cap 主要防御"混合档 MIXED 叠加重复"。
func DedupeAndCapAssignments(in []Assignment, maxPerProj int) []Assignment {
	if len(in) == 0 {
		return in
	}
	out := make([]Assignment, 0, len(in))
	prio := map[string]int{
		predefDomainAdminId():   10,
		predefProjectOwnerId():  9,
		predefProjectEditorId(): 5,
		predefProjectViewerId(): 3,
		predefMemberId():        2,
	}
	// 先按优先级降序排，cap 时保留高优先级
	bucket := map[string][]Assignment{}
	for _, a := range in {
		bucket[a.ProjectId] = append(bucket[a.ProjectId], a)
	}
	for pid, arr := range bucket {
		sortSlice(arr, func(a, b Assignment) bool {
			return prio[a.RoleId] > prio[b.RoleId]
		})
		if maxPerProj > 0 && len(arr) > maxPerProj {
			log.Warningf("tyc BuildVirtualAssignments: project %s has %d roles > cap %d, truncate", pid, len(arr), maxPerProj)
			arr = arr[:maxPerProj]
		}
		out = append(out, arr...)
	}
	return out
}

// FetchUserProjectRolesWithIdpScope wrapper（内部版，接受完整 *TycScope）：
//  真实 assignments（管理员手工授予 src=manual） ∪ 虚拟 assignments（TYC 每次派生）
func fetchUserProjectRolesInternal(
	ctx context.Context,
	userId, projectId string,
	realFn func(userId, projectId string) ([]models.SRole, error),
	scope *TycScope, idx *OrgTreeIndex,
	maxPerProj int,
) ([]models.SRole, error) {
	real, err := realFn(userId, projectId)
	if err != nil {
		return nil, errors.Wrap(err, "real FetchUserProjectRoles")
	}
	if scope == nil {
		return real, nil
	}
	virt, err := BuildVirtualAssignments(ctx, scope, idx, maxPerProj)
	if err != nil {
		return nil, err
	}
	merged := make([]models.SRole, 0, len(real)+len(virt))
	merged = append(merged, real...)
	seen := map[string]struct{}{}
	for _, r := range real {
		seen[r.Id] = struct{}{}
	}
	for _, a := range virt {
		if a.ProjectId != projectId {
			continue
		}
		if _, ok := seen[a.RoleId]; ok {
			continue
		}
		role := models.SRole{}
		role.Id = a.RoleId
		merged = append(merged, role)
		seen[a.RoleId] = struct{}{}
	}
	return merged, nil
}

// FetchUserProjectRolesWithIdpScope 公开入口（接受 scopeJSON string）：
// 供 tokens/token.go 调用。内部解析 JSON 为 TycScope 后委托内部版。
// 非 TYC 用户（scopeJSON 为空）直接返回 real roles。
func FetchUserProjectRolesWithIdpScope(
	ctx context.Context,
	userId, projectId string,
	realFn func(userId, projectId string) ([]models.SRole, error),
	scopeJSON string,
	maxPerProj int,
) ([]models.SRole, error) {
	if len(scopeJSON) == 0 {
		return realFn(userId, projectId)
	}
	scope := &TycScope{}
	if err := json.Unmarshal([]byte(scopeJSON), scope); err != nil {
		log.Warningf("tyc FetchUserProjectRolesWithIdpScope: unmarshal scopeJSON fail: %v, fallback to real", err)
		return realFn(userId, projectId)
	}
	if len(scope.CloudRoleId) == 0 {
		scope.CloudRoleId = MapTycRoleToPredefined(scope.DistrictAdm, scope.TycRoleName)
	}
	return fetchUserProjectRolesInternal(ctx, userId, projectId, realFn, scope, nil, maxPerProj)
}

// ── utils ──────────────────────────────────────────────────────────────────

func sortSlice[T any](arr []T, less func(a, b T) bool) {
	sort.Slice(arr, func(i, j int) bool { return less(arr[i], arr[j]) })
}

// CredToken 上下文里把 scope 挂进去的最小 helper（给 auth handler / middleware 注入用）

type tycScopeKey struct{}

func WithTycScope(ctx context.Context, s *TycScope) context.Context {
	return context.WithValue(ctx, tycScopeKey{}, s)
}

func GetTycScope(ctx context.Context) *TycScope {
	v, _ := ctx.Value(tycScopeKey{}).(*TycScope)
	return v
}

// TycScopeTTL 检查 ScopeSnapshot 是否过期（返回 true = 需要异步刷新）
func TycScopeTTLExpired(s *TycScope, nowUnix, ttlSeconds int64) bool {
	if s == nil {
		return false
	}
	if ttlSeconds <= 0 {
		ttlSeconds = 60 // 默认 60s
	}
	if s.SnapshotAt <= 0 {
		return true // webhook 置 0 → 立即刷新
	}
	return nowUnix-s.SnapshotAt > ttlSeconds
}
