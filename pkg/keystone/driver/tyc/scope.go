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
	"strings"
	"sync"
	"time"

	"yunion.io/x/jsonutils"
	"yunion.io/x/pkg/errors"

	api "yunion.io/x/onecloud/pkg/apis/identity"
	models "yunion.io/x/onecloud/pkg/keystone/models"
	"yunion.io/x/onecloud/pkg/mcclient"
)

// ── DataScope 四档枚举 ─────────────────────────────────────────────────────

type DataScopeLevel string

const (
	DataScopeDomainAll  DataScopeLevel = "DOMAIN_ALL"  // ① 域的所有
	DataScopeOrgSubtree DataScopeLevel = "ORG_SUBTREE" // ② 某组织及下级
	DataScopeProjectSet DataScopeLevel = "PROJECT_SET" // ③ 指定项目
	DataScopeMixed      DataScopeLevel = "MIXED"       // ④ 混合
)

type DataScope struct {
	Level      DataScopeLevel `json:"level"`
	OrgId      string         `json:"orgId,omitempty"`      // ORG_SUBTREE 必填
	OrgIds     []string       `json:"orgIds,omitempty"`     // MIXED：多个组织子树（如 1 人管两市）
	ProjectIds []string       `json:"projectIds,omitempty"` // PROJECT_SET / MIXED
}

// ── TycScope 事实快照 ──────────────────────────────────────────────────────

// TycScope 是 tydic 事实 → cloudpods 鉴权的输入。
// 每次登录全量覆盖 SUser.Extra['tyc_scope']；SnapshotAt 用于 ScopeTTL 控制运行中刷新。
type TycScope struct {
	TenantId    string    `json:"tenantId"`
	TenantCode  string    `json:"tenantCode"`
	OrgId       string    `json:"orgId"`       // 用户所属组织（来自 SystemUserDetail + SUser.Extra 归档）
	DistrictAdm int       `json:"districtAdm"` // 1100=全区, 1000=普通
	TycRoleName string    `json:"tycRoleName"` // 原始 tydic sysRoleName（不映射，仅排查用）
	CloudRoleId string    `json:"cloudRoleId"` // 归一后映射到预置角色 ID：domainadmin/project_editor/project_viewer/member/viewer 之一
	DataScope   DataScope `json:"dataScope"`
	SnapshotAt  int64     `json:"snapshotAt"`  // unix 秒，webhook 触发刷新时写 0
}

// 预置角色名（与 pkg/keystone/locale/predefined_policies.go 对齐）
const (
	PredefRoleNameDomainAdmin   = "domainadmin"
	PredefRoleNameProjectOwner  = "project_owner"
	PredefRoleNameProjectEditor = "project_editor"
	PredefRoleNameProjectViewer = "project_viewer"
	PredefRoleNameMember        = "member"
	PredefRoleNameViewer        = "project_viewer"
)

// roleIdCache 进程级缓存：roleName → SRole.Id（按需查一次，之后复用）
var (
	roleIdCacheMu   sync.Mutex
	roleIdCacheMap  = map[string]string{}
)

// resolveRoleId 按角色名查真实 SRole.Id，带进程级缓存
func resolveRoleId(roleName string) string {
	roleIdCacheMu.Lock()
	if id, ok := roleIdCacheMap[roleName]; ok {
		roleIdCacheMu.Unlock()
		return id
	}
	roleIdCacheMu.Unlock()

	role, err := models.RoleManager.FetchRoleByName(roleName, "", "")
	if err != nil || role == nil {
		return roleName
	}
	roleIdCacheMu.Lock()
	roleIdCacheMap[roleName] = role.Id
	roleIdCacheMu.Unlock()
	return role.Id
}

// InvalidateRoleIdCache 供热加载/测试时清除缓存
func InvalidateRoleIdCache() {
	roleIdCacheMu.Lock()
	roleIdCacheMap = map[string]string{}
	roleIdCacheMu.Unlock()
}

// 兼容旧占位符常量（供 DedupeAndCapAssignments 优先级 map 使用）——值动态解析
func predefDomainAdminId() string   { return resolveRoleId(PredefRoleNameDomainAdmin) }
func predefProjectOwnerId() string  { return resolveRoleId(PredefRoleNameProjectOwner) }
func predefProjectEditorId() string { return resolveRoleId(PredefRoleNameProjectEditor) }
func predefProjectViewerId() string { return resolveRoleId(PredefRoleNameProjectViewer) }
func predefMemberId() string        { return resolveRoleId(PredefRoleNameMember) }

// ── 本文件内小型工具（与 client.go 同名工具通过作用域区分，前缀 scope_） ─

func scope_toLowerTrim(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func scope_containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func scope_nonEmptyUnique(xs ...string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if len(x) == 0 {
			continue
		}
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}

// MapTycRoleToPredefined：tydic 角色名 → 预置角色真实 ID。不建自定义角色。
func MapTycRoleToPredefined(districtAdm int, tycRoleName string) string {
	if districtAdm == 1100 {
		return predefDomainAdminId()
	}
	name := scope_toLowerTrim(tycRoleName)
	switch {
	case scope_containsAny(name, "admin", "管理员"):
		return predefProjectOwnerId()
	case scope_containsAny(name, "editor", "编辑", "运维", "操作员"):
		return predefProjectEditorId()
	case scope_containsAny(name, "viewer", "只读", "访客"):
		return predefProjectViewerId()
	case scope_containsAny(name, "member", "成员"):
		return predefMemberId()
	}
	return predefMemberId()
}

// BuildTycScopeFromDetail 把 tydic 返回的 SystemUserDetail → TycScope。
// 优先级：直接读 705 dataScope / orgScope / projectScope（有字段时） → 回退按 districtAdm / sysRoleId / projectId 推测。
func BuildTycScopeFromDetail(ctx context.Context, conf api.STycIdpConfigOptions, detail *SystemUserDetail, idx *OrgTreeIndex) (*TycScope, error) {
	if detail == nil {
		return nil, fmt.Errorf("nil SystemUserDetail")
	}
	scope := &TycScope{
		TenantId:    detail.TenantId,
		TenantCode:  detail.TenantCode,
		OrgId:       detail.OrgId,
		DistrictAdm: detail.DistrictAdm,
		TycRoleName: detail.SysRoleName,
		CloudRoleId: MapTycRoleToPredefined(detail.DistrictAdm, detail.SysRoleName),
		SnapshotAt:  time.Now().Unix(),
	}

	// ── 1) 优先：705 接口（如提前拉到）暴露的 DataScope 字段（最准确口径） ──
	if d := detail.PrivsDataScope; d != nil && len(string(d.Level)) > 0 {
		scope.DataScope = *d
		return scope, nil
	}

	// ── 2) 回退推测口径（Phase 0 如发现 705 无 dataScope 字段，用这套） ──
	projectIds := scope_nonEmptyUnique(append([]string{detail.ProjectId}, detail.ProjectIdList...)...)
	switch {
	case detail.DistrictAdm == 1100:
		scope.DataScope = DataScope{Level: DataScopeDomainAll}
	case detail.SysRoleId < 0 || (len(projectIds) > 0 && len(detail.OrgId) == 0):
		// 项目维度登录（sysRoleId<0 是 tydic 项目维度登录约定）
		scope.DataScope = DataScope{Level: DataScopeProjectSet, ProjectIds: projectIds}
	case len(detail.OrgId) > 0:
		// 普通 + 有组织归属 → 组织子树
		scope.DataScope = DataScope{Level: DataScopeOrgSubtree, OrgId: detail.OrgId}
	default:
		// 什么都没有 → 项目级兜底（只看自己 sysUser 所属项目）
		scope.DataScope = DataScope{Level: DataScopeProjectSet, ProjectIds: projectIds}
	}
	return scope, nil
}

// ── SUser.Extra['tyc_scope'] 编解码 helper ─────────────────────────────────
//
// keystone/models SUser.Extra 的真实类型 = *jsonutils.JSONDict（通过 SRecordChecksumResourceBase 继承的
// SExtraizedResourceBase 字段）。读写统一用 Set/GetString 而不是 map 转换避免类型错。

const extraTycScopeKey = "tyc_scope"

// SaveToUserExtra 把 scope 写进 user.Extra。
// 调用方需要在之后显式调用 UserManager.Update(...) 把 Extra 持久化（因为这里只改内存）。
func SaveToUserExtra(u *models.SUser, s *TycScope) error {
	if u == nil || s == nil {
		return fmt.Errorf("nil user/scope")
	}
	b, err := json.Marshal(s)
	if err != nil {
		return errors.Wrap(err, "marshal tyc scope")
	}
	if u.Extra == nil {
		u.Extra = jsonutils.NewDict()
	}
	u.Extra.Add(jsonutils.NewString(string(b)), extraTycScopeKey)
	return nil
}

// LoadFromUserExtra 从 SUser.Extra 反解 TycScope，取不到 = nil（非 TYC 用户）
func LoadFromUserExtra(u *models.SUser) (*TycScope, error) {
	if u == nil || u.Extra == nil {
		return nil, nil
	}
	v, err := u.Extra.GetString(extraTycScopeKey)
	if err != nil || len(v) == 0 {
		return nil, nil // 没有 tyc_scope = 非 TYC 用户，正常返回 nil（err 丢弃）
	}
	out := &TycScope{}
	if err := json.Unmarshal([]byte(v), out); err != nil {
		return nil, errors.Wrap(err, "unmarshal tyc scope json")
	}
	return out, nil
}

// LoadFromCred 从 mcclient.TokenCredential 取 TycScope（运行时鉴权用）。
// 如果 Credential 类型里未直接暴露 SUser，则先查 models.UserManager 再 LoadFromUserExtra。
// 这里给一个最小占位接口；实际按 types 调整。
func LoadFromCred(ctx context.Context, cred mcclient.TokenCredential) (*TycScope, error) {
	if cred == nil {
		return nil, nil
	}
	// TODO: 从 cred 取 userId → models.UserManager.FetchById → LoadFromUserExtra
	return nil, nil
}

// ── OrgTreeIndex：同步后组织/项目的本地索引缓存（进程内 LRU 由上层持有） ────

type OrgTreeIndex struct {
	TenantId               string
	OrgAncestorsByOrgId    map[string][]string          // orgId → [根…self]
	BindProjectByOrgId     map[string]string            // orgId → ORG-xxx 组织项目 SProject.Id
	DomainRootOrgProjectId string                       // ORG-O000 的 ProjectId（给 DOMAIN_ALL 档挂 role）
}

func NewOrgTreeIndex(tenantId string) *OrgTreeIndex {
	return &OrgTreeIndex{
		TenantId:            tenantId,
		OrgAncestorsByOrgId: map[string][]string{},
		BindProjectByOrgId:  map[string]string{},
	}
}

// AncestorsIncludingSelf：返回 orgId 的完整祖先链（含自己），供 TagFilter 做 ProjectTags/org 过滤
func (i *OrgTreeIndex) AncestorsIncludingSelf(orgId string) []string {
	if i == nil {
		return nil
	}
	return i.OrgAncestorsByOrgId[orgId]
}

// BindProjectId 取某个 orgId 对应的 ORG-xxx 组织项目 ID（同步阶段写）
func (i *OrgTreeIndex) BindProjectId(orgId string) string {
	if i == nil {
		return ""
	}
	return i.BindProjectByOrgId[orgId]
}

// ListBusinessProjectIdsUnderOrg 返回指定 org 子树下的所有业务项目 ID。
// 关键：用同步时写好的 ProjectTags['org'] 做一次 JSON_CONTAINS 查询，O(1) 返回结果，不递归树。
// 这里给一个占位实现，集成时换成真实 models.ProjectManager 的 tag 查询。
func (i *OrgTreeIndex) ListBusinessProjectIdsUnderOrg(ctx context.Context, orgId string) ([]string, error) {
	anc := i.AncestorsIncludingSelf(orgId)
	if len(anc) == 0 {
		return nil, nil
	}
	// 真实 SQL：SELECT id FROM projects WHERE domain_id=? AND JSON_CONTAINS(project_tags->'$.org', JSON_QUOTE(?))
	// 任何一个祖先匹配都算在该组织子树下（所以 SQL 是 ANY(JSON_CONTAINS) / ProjectTagsContainsAny）
	_ = anc
	// TODO: 接真正的 ProjectManager 子查询
	return nil, nil
}
