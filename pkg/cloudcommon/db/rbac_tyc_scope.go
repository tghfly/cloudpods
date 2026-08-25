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

package db

import (
	"context"
	"fmt"

	"yunion.io/x/log"
	"yunion.io/x/pkg/util/rbacscope"
	"yunion.io/x/sqlchemy"
)

// ── 双管道授权 · 管道 B：TagFilter（行级追加过滤） ──────────────────────────
//
// 定位：在 SharableManagerFilterByOwner / SUserResourceBaseManager.FilterByOwner 【执行完之后】
//       把本函数的返回值再套一层，实现 TYC 用户专属数据权限行限制。
//       非 TYC 用户（scope==nil）直接透传 q，零影响。
//
// 循环依赖规避：db 包 不 import tyc 包。tyc 登录 handler 调 SetTycScopeFilterInCtx
//       把 DTO 写入 ctx；本文件只认 DTO，不认 tyc 内部结构。
//
// 四档 DataScope 映射到 SQL：
//   ① DOMAIN_ALL   → 不加额外过滤（已过 AllowScope=domain，域内全放行）
//   ② ORG_SUBTREE  → tenant_id IN (子业务 project 集合)；子集合由 ProjectTags['org'] 祖先链推导
//   ③ PROJECT_SET  → tenant_id IN (scope.ProjectIds)
//   ④ MIXED        → tenant_id IN (org_subtree_projects ∪ scope.ProjectIds，去重)
//
// 注意：只有 ResourceScope=ScopeProject（绝大多数业务资源）才追加 tenant_id 过滤；
//       ScopeDomain 资源（域/角色/服务等）不做项目层限制（在 AllowScope 层已挡）。

// TycScopeFilterDTO db 包可识别的最小 scope（tyc→db 的弱契约 DTO）。
// tyc/authpipes.go 登录阶段调用 SetTycScopeFilterInCtx 写入；鉴权阶段本文件读取。
type TycScopeFilterDTO struct {
	Level      string   `json:"level"`      // DOMAIN_ALL / ORG_SUBTREE / PROJECT_SET / MIXED
	DomainId   string   `json:"domainId"`   // tydic tenantId → cloudpods domain_id
	OrgId      string   `json:"orgId"`      // ORG_SUBTREE 单组织
	OrgIds     []string `json:"orgIds"`     // MIXED 多组织（不含 OrgId 重复项）
	ProjectIds []string `json:"projectIds"` // PROJECT_SET / MIXED
}

// tycScopeFilterCtxKey context key（公共，给 tyc 包用——通过 SetTycScopeFilterInCtx 封装）
type tycScopeFilterCtxKey struct{}

// SetTycScopeFilterInCtx 把 DTO 写入 ctx（tyc 登录 handler / 中间件调用）。
// s == nil 等价于"非 TYC 用户"，不写入。
func SetTycScopeFilterInCtx(ctx context.Context, s *TycScopeFilterDTO) context.Context {
	if s == nil {
		return ctx
	}
	return context.WithValue(ctx, tycScopeFilterCtxKey{}, s)
}

// GetTycScopeFilterFromCtx 从 ctx 取 DTO；取不到 = nil（非 TYC 用户，直接透传）。
func GetTycScopeFilterFromCtx(ctx context.Context) *TycScopeFilterDTO {
	v, _ := ctx.Value(tycScopeFilterCtxKey{}).(*TycScopeFilterDTO)
	return v
}

// ApplyPolicyFilterWithTycScope 管道 B 入口。
//
// 参数：
//   q          = 原生 SharableManagerFilterByOwner 跑完之后的 *SQuery（已经按 scope+owner 过滤好）
//   manager    = 当前资源 manager（取 ResourceScope、资源表别名等）
//   resScope   = manager.ResourceScope() 预求值（避免多次函数调用）
//   scope      = AllowScope 实际返回的 rbacscope（System/Domain/Project/User）
//
// 语义：DOMAIN_ALL 档直接返回 q（域级角色已可看全域）；其他三档按 ProjectId 集合收窄 tenant_id。
func ApplyPolicyFilterWithTycScope(
	ctx context.Context,
	q *sqlchemy.SQuery,
	manager IModelManager,
	resScope rbacscope.TRbacScope,
	_ rbacscope.TRbacScope,
) *sqlchemy.SQuery {
	ts := GetTycScopeFilterFromCtx(ctx)
	if ts == nil {
		return q // 非 TYC 用户 → 零影响
	}
	// 仅对 ScopeProject 资源（绝大多数 IaaS 业务对象）追加行过滤。
	// ScopeDomain 资源（domain/role/service/endpoint 等）不在此处做项目级限制——AllowScope 判定挡在前面。
	if resScope != rbacscope.ScopeProject {
		return q
	}
	pids, err := resolveProjectIdsForTycScope(ctx, ts, manager)
	if err != nil {
		log.Errorf("[tyc TagFilter] resolveProjectIds fail: %v → narrow to empty (SAFE)", err)
		return q.Filter(sqlchemy.In(q.Field("tenant_id"), []string{}))
	}
	switch ts.Level {
	case "DOMAIN_ALL":
		return q // 不额外加限制（AllowScope=Domain 已保证只看同域，已经是域的所有）
	case "ORG_SUBTREE", "PROJECT_SET", "MIXED":
		if len(pids) == 0 {
			// 没有可访问项目 → 收窄到空集合。注意：这里不能用 FALSE 因为会误杀 public=system 的对象。
			// 所以只加 tenant_id IN (空)，对 system-scope public 对象仍放行（因为外层 OR 已处理）。
			return q.Filter(sqlchemy.In(q.Field("tenant_id"), []string{}))
		}
		// tenant_id = 项目 ID（cloudpods 项目资源的 tenant_id 列即 project_id）。
		return q.Filter(sqlchemy.In(q.Field("tenant_id"), pids))
	default:
		log.Errorf("[tyc TagFilter] unknown scope level=%q → narrow to empty", ts.Level)
		return q.Filter(sqlchemy.In(q.Field("tenant_id"), []string{}))
	}
}

// resolveProjectIdsForTycScope 把 (DOMAIN_ALL / ORG_SUBTREE / PROJECT_SET / MIXED) → 实际可访问 projectId 集合。
//
// ORG_SUBTREE / MIXED 的 org 子树：依赖同步时写入的 ProjectTags['org']（由 syncOrgTree / syncProjects 拍平了祖先链）。
// 具体 SQL（对 projects 表）：
//   SELECT id FROM projects
//   WHERE domain_id = ?
//     AND JSON_CONTAINS(project_tags->'$.org', JSON_QUOTE(?))   -- 任一祖先命中
//
// 这里用 Query + ObjectIdQueryWithTagFilters 风格（与 sharablebase.go:320 完全一致），
// 避免手写 JSON_CONTAINS，兼容多数据库。
func resolveProjectIdsForTycScope(
	ctx context.Context,
	ts *TycScopeFilterDTO,
	_ IModelManager,
) ([]string, error) {
	switch ts.Level {
	case "DOMAIN_ALL":
		return nil, nil
	case "PROJECT_SET":
		return dedupeString(ts.ProjectIds), nil
	case "ORG_SUBTREE":
		orgIds := []string{}
		if len(ts.OrgId) > 0 {
			orgIds = append(orgIds, ts.OrgId)
		}
		return resolveOrgSubtreeProjectIds(ctx, ts.DomainId, orgIds)
	case "MIXED":
		orgIds := append([]string(nil), ts.OrgIds...)
		if len(ts.OrgId) > 0 {
			orgIds = append(orgIds, ts.OrgId)
		}
		fromOrgs, err := resolveOrgSubtreeProjectIds(ctx, ts.DomainId, dedupeString(orgIds))
		if err != nil {
			return nil, err
		}
		return dedupeString(append(fromOrgs, ts.ProjectIds...)), nil
	}
	return nil, fmt.Errorf("unknown tyc scope level=%q", ts.Level)
}

// resolveOrgSubtreeProjectIds 给定 orgId 集合，返回"所有归属在这些 org 子树下的业务项目 ID"。
//
// 匹配规则：项目 ProjectTags['org'] 数组中 包含 orgId 祖先链的 任意一个元素（即"该 org 及其子级"语义）。
// 实现通过 OrgSubtreeProjectResolver 回调（由 keystone models 包在 init 时注册），避免 db→models 循环导入。
func resolveOrgSubtreeProjectIds(ctx context.Context, domainId string, orgIds []string) ([]string, error) {
	if len(orgIds) == 0 {
		return nil, nil
	}
	if orgSubtreeProjectResolver == nil {
		return nil, nil
	}
	return orgSubtreeProjectResolver(ctx, domainId, orgIds)
}

// OrgSubtreeProjectResolverFunc 回调签名：给定 domainId + orgIds，返回该域下 ProjectTags['org'] 包含任一 orgId 的所有项目 ID
type OrgSubtreeProjectResolverFunc func(ctx context.Context, domainId string, orgIds []string) ([]string, error)

var orgSubtreeProjectResolver OrgSubtreeProjectResolverFunc

// RegisterOrgSubtreeProjectResolver 由 keystone/models 在 init 时注册真实查询实现
func RegisterOrgSubtreeProjectResolver(fn OrgSubtreeProjectResolverFunc) {
	orgSubtreeProjectResolver = fn
}

// ── util ────────────────────────────────────────────────────────────────────

func dedupeString(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ── 请求级 TycScope DTO 注入 ────────────────────────────────────────────────

// TycScopeLoaderFunc 回调签名：给定 userId，从 DB 加载 TycScopeFilterDTO。
// 由 keystone/models 在 init 时注册（避免 db→models 循环导入）。
type TycScopeLoaderFunc func(ctx context.Context, userId string) *TycScopeFilterDTO

var tycScopeLoader TycScopeLoaderFunc

// RegisterTycScopeLoader 注册从 userId 加载 TycScope 的回调
func RegisterTycScopeLoader(fn TycScopeLoaderFunc) {
	tycScopeLoader = fn
}

// InjectTycScopeToCtxIfNeeded 在请求级注入 TycScope DTO 到 ctx。
// 如果 ctx 中已有 DTO（登录请求自带）则跳过。
// 如果 loader 未注册或 userId 为空则跳过（非 TYC 用户，零影响）。
func InjectTycScopeToCtxIfNeeded(ctx context.Context, userId string) context.Context {
	if GetTycScopeFilterFromCtx(ctx) != nil {
		return ctx
	}
	if tycScopeLoader == nil || len(userId) == 0 {
		return ctx
	}
	dto := tycScopeLoader(ctx, userId)
	if dto == nil {
		return ctx
	}
	return SetTycScopeFilterInCtx(ctx, dto)
}
