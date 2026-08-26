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

// ── ActionLevel 动作权限 3 档枚举（替代原角色映射） ────────────────────────

type ActionLevel string

const (
	ActionLevelFull     ActionLevel = "full"     // 全部动作：list/get/create/update/delete/perform
	ActionLevelEditor   ActionLevel = "editor"   // 编辑档：list/get/update/perform（禁 create/delete）
	ActionLevelReadonly ActionLevel = "readonly" // 只读档：list/get（禁 create/update/delete/perform）
)

// ActionOverride 支持 705 接口返回的逐资源精确覆盖（优先级高于 ActionLevel 通配）
type ActionOverride struct {
	Service  string   `json:"service"`
	Resource string   `json:"resource,omitempty"`
	Allow    []string `json:"allow"`
	Deny     []string `json:"deny,omitempty"`
}

// ── TycScope 事实快照 ──────────────────────────────────────────────────────

type TycScope struct {
	TenantId        string           `json:"tenantId"`
	TenantCode      string           `json:"tenantCode"`
	OrgId           string           `json:"orgId"`
	DistrictAdm     int              `json:"districtAdm"`
	TycRoleName     string           `json:"tycRoleName"`
	ActionLevel     ActionLevel      `json:"actionLevel"`
	ActionOverrides []ActionOverride `json:"actionOverrides,omitempty"`
	DataScope       DataScope        `json:"dataScope"`
	SnapshotAt      int64            `json:"snapshotAt"`
}

// ActionsForLevel 返回 ActionLevel 对应的允许动作列表
func ActionsForLevel(level ActionLevel) []string {
	switch level {
	case ActionLevelFull:
		return []string{"list", "get", "create", "update", "delete", "perform"}
	case ActionLevelEditor:
		return []string{"list", "get", "update", "perform"}
	case ActionLevelReadonly:
		return []string{"list", "get"}
	default:
		return []string{"list", "get"}
	}
}

// MapTycToActionLevel 从 tydic 事实推导 ActionLevel（不映射角色）
func MapTycToActionLevel(districtAdm int, tycRoleName string) ActionLevel {
	if districtAdm == 1100 {
		return ActionLevelFull
	}
	name := strings.ToLower(strings.TrimSpace(tycRoleName))
	switch {
	case strContainsAny(name, "admin", "管理员", "owner"):
		return ActionLevelFull
	case strContainsAny(name, "editor", "编辑", "运维", "操作员"):
		return ActionLevelEditor
	default:
		return ActionLevelReadonly
	}
}

// ── 内部工具 ──────────────────────────────────────────────────────────────

func strContainsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func nonEmptyUnique(xs ...string) []string {
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
		ActionLevel: MapTycToActionLevel(detail.DistrictAdm, detail.SysRoleName),
		SnapshotAt:  time.Now().Unix(),
	}

	// ── 1) 优先：705 接口（如提前拉到）暴露的 DataScope 字段（最准确口径） ──
	if d := detail.PrivsDataScope; d != nil && len(string(d.Level)) > 0 {
		scope.DataScope = *d
		return scope, nil
	}

	// ── 2) 回退推测口径（Phase 0 如发现 705 无 dataScope 字段，用这套） ──
	projectIds := nonEmptyUnique(append([]string{detail.ProjectId}, detail.ProjectIdList...)...)
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
	OrgAncestorsByOrgId    map[string][]string // orgId → [根…self]
	BindProjectByOrgId     map[string]string   // orgId → ORG-xxx 组织项目 SProject.Id
	DomainRootOrgProjectId string              // ORG-O000 的 ProjectId（给 DOMAIN_ALL 档挂 role）
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
