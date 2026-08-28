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
	"fmt"

	"yunion.io/x/jsonutils"
	"yunion.io/x/log"
	"yunion.io/x/pkg/errors"

	api "yunion.io/x/onecloud/pkg/apis/identity"
	"yunion.io/x/onecloud/pkg/cloudcommon/db"
	"yunion.io/x/onecloud/pkg/httperrors"
	"yunion.io/x/onecloud/pkg/keystone/models"
	"yunion.io/x/onecloud/pkg/mcclient"
)

// STycDriver tydic SSO 驱动壳实现 driver.IIdentityBackend。
//
// v2 关键约定：
//   - Authenticate 负责 "token → SystemUserDetail" 校验 + idp.SyncOrCreateDomainAndUser 写域/用户；
//     用户 Extra 同步写 raw tydic 字段 + tyc_scope JSON 快照。
//   - Sync() 负责同步事实（组织树 / 项目 / 可选用户列表），不写 assignments；
//   - 授权（角色/项目绑定）完全不在此落库，由 ScopeResolver 在每次鉴权时实时派生虚拟 assignments；
//   - PostAuthenticate 由 tokens/auth.go 通过鸭子接口调用：把 TycScope → db.TycScopeFilterDTO 写 ctx。
type STycDriver struct {
	idpId          string
	idpName        string
	template       string
	targetDomainId string
	conf           api.STycIdpConfigOptions
	client         *TYCHttpClient
	orgIdx         *OrgTreeIndex
	// lastDetail 缓存 Authenticate 里 ExchangeToken 反解出来的 SystemUserDetail，
	// 给 PostAuthenticate 用（避免再调一次 705 接口）。单 goroutine 串行（Authenticate→PostAuthenticate），不并发。
	lastDetail *SystemUserDetail
}

// NewTycDriver 构造器，被 class.go 注册时调用
func NewTycDriver(idpId, idpName, template, targetDomainId string, tconf api.TConfigs) (*STycDriver, error) {
	conf := api.STycIdpConfigOptions{}
	if blob, ok := tconf[api.IdentityDriverTyc]; ok {
		if err := jsonutils.Marshal(blob).Unmarshal(&conf); err != nil {
			return nil, errors.Wrap(err, "parse tyc driver idp config")
		}
	}
	cli, err := NewTYCHttpClient(conf)
	if err != nil {
		return nil, errors.Wrap(err, "new tyc http client")
	}
	return &STycDriver{
		idpId:          idpId,
		idpName:        idpName,
		template:       template,
		targetDomainId: targetDomainId,
		conf:           conf,
		client:         cli,
		orgIdx:         NewOrgTreeIndex(conf.TenantId),
	}, nil
}

// Authenticate 实现 IIdentityBackend.Authenticate。
//
// 流程（对齐 CAS 模式）：
//  1. ident.Password.User.Password = tydic 门户 token（ident.Password.User.Name = sysUserCode）
//  2. client.ExchangeToken → SystemUserDetail
//  3. idp.SyncOrCreateDomainAndUser → 写 SDomain + SUser + id_mapping
//  4. SUser.Extra 写 raw tydic 字段 + BuildTycScopeFromDetail().MarshalJSON 快照
//  5. UserManager.Update(ctx, user, diff) → 持久化 Extra
//  6. 缓存 detail 到 self.lastDetail（给 PostAuthenticate 重建 DTO，不必再查 DB）
//  7. FetchUserExtended → 返回 API 类型
func (self *STycDriver) Authenticate(ctx context.Context, identity mcclient.SAuthenticationIdentity) (*api.SUserExtended, error) {
	token := identity.Password.User.Password
	// Password.User.Id：前端传了 transaction_id 就用它，保持与 tydic 防重放一致；
	// 空串则驱动内部自生成 newTxnId()。
	extTxnId := identity.Password.User.Id
	detail, err := self.client.ExchangeToken(ctx, token, extTxnId)
	if err != nil {
		return nil, errors.Wrap(err, "tyc token exchange (identity acquire: HARD FAIL)")
	}
	if detail == nil {
		return nil, httperrors.NewUnauthorizedError("empty tydic SystemUserDetail after token exchange")
	}
	idp, err := models.IdentityProviderManager.FetchIdentityProviderById(self.idpId)
	if err != nil {
		return nil, errors.Wrap(err, "FetchIdentityProviderById for tyc")
	}
	domain, usr, err := idp.SyncOrCreateDomainAndUser(
		ctx,
		detail.TenantId, detail.TenantCode,
		detail.SysUserCode, detail.StaffName,
	)
	if err != nil {
		return nil, errors.Wrap(err, "idp.SyncOrCreateDomainAndUser (tyc)")
	}
	// 显示名 / 手机号：同步回写 Update（如果不同）
	if len(detail.StaffName) > 0 && usr.Displayname != detail.StaffName {
		usr.Displayname = detail.StaffName
	}
	if len(detail.PwdSmsTel) > 0 && usr.Mobile != detail.PwdSmsTel {
		usr.Mobile = detail.PwdSmsTel
	}
	// Extra：raw tydic 字段 + tyc_scope 快照
	if usr.Extra == nil {
		usr.Extra = jsonutils.NewDict()
	}
	addStr := func(k, v string) {
		if v != "" {
			usr.Extra.Add(jsonutils.NewString(v), k)
		}
	}
	addInt := func(k string, v int) {
		usr.Extra.Add(jsonutils.NewInt(int64(v)), k)
	}
	addStrArr := func(k string, v []string) {
		if len(v) > 0 {
			usr.Extra.Add(jsonutils.Marshal(v), k)
		}
	}
	addStr("tenant_id", detail.TenantId)
	addStr("tenant_code", detail.TenantCode)
	addStr("tenant_name", detail.TenantName)
	addStr("org_id", detail.OrgId)
	addStr("org_name", detail.OrgName)
	addStr("region_id", detail.RegionId)
	addStr("region_code", detail.RegionCode)
	addStr("region_name", detail.RegionName)
	addStr("staff_id", detail.StaffId)
	addStr("staff_name", detail.StaffName)
	addInt("sys_role_id", detail.SysRoleId)
	addStr("sys_role_name", detail.SysRoleName)
	addInt("district_adm", detail.DistrictAdm)
	addStr("pwd_sms_tel", detail.PwdSmsTel)
	addStrArr("project_id_list_tyc", detail.ProjectIdList)
	scope, err := BuildTycScopeFromDetail(ctx, self.conf, detail, self.orgIdx)
	if err == nil && scope != nil {
		if e2 := SaveToUserExtra(usr, scope); e2 != nil {
			log.Warningf("tyc SaveToUserExtra fail: %v", e2)
		}
	}
	// 写回 user（displayname/mobile/extra）：调用 db.Update 走标准路径（不直写 TableSpec）
	if _, err := db.Update(usr, func() error {
		// db.Update 的 closure 内对 model 原地修改后 return nil，由框架 persist
		// （这里的 usr 已经在 closure 外的内存里改好了，return nil 让框架落库）
		return nil
	}); err != nil {
		return nil, errors.Wrap(err, "db.Update tyc user (extra/displayname/mobile)")
	}
	extUser, err := models.UserManager.FetchUserExtended(usr.Id, "", "", "")
	if err != nil {
		return nil, errors.Wrap(err, "UserManager.FetchUserExtended (tyc)")
	}
	// 缓存 detail，供 PostAuthenticate 使用（同请求内，顺序调用）
	self.lastDetail = detail
	if len(extUser.AuditIds) == 0 {
		extUser.AuditIds = []string{detail.SysUserCode}
	}
	// 用完把 domain 放一边，避免 linter 报 unused
	_ = domain
	return extUser, nil
}

// PostAuthenticate 实现 tokens/auth.go 中的鸭子接口 iTycScopeFlusher。
// 被 authUserByTYC 在 backend.Authenticate + Sync 之后调用。
// 职责：把 self.lastDetail（Authenticate 里缓存的）/ DB 里的 TycScope → 转 db.TycScopeFilterDTO → 写入 ctx。
func (self *STycDriver) PostAuthenticate(ctx context.Context, usrExt *api.SUserExtended) (context.Context, error) {
	if usrExt == nil || len(usrExt.Id) == 0 {
		return ctx, nil
	}
	// 取 TycScope：优先用缓存的 lastDetail 重建；兜底从 DB SUser 反解
	var scope *TycScope
	if self.lastDetail != nil {
		if s, e := BuildTycScopeFromDetail(ctx, self.conf, self.lastDetail, self.orgIdx); e == nil {
			scope = s
		}
	}
	if scope == nil {
		if raw, e := models.UserManager.FetchById(usrExt.Id); e == nil {
			if suser, ok := raw.(*models.SUser); ok {
				scope, _ = LoadFromUserExtra(suser)
			}
		}
	}
	if scope == nil {
		return ctx, nil
	}
	// TycScope → db.TycScopeFilterDTO
	dto := &db.TycScopeFilterDTO{
		DomainId:   scope.TenantId,
		ProjectIds: []string{},
	}
	switch scope.DataScope.Level {
	case DataScopeDomainAll:
		dto.Level = "DOMAIN_ALL"
	case DataScopeOrgSubtree:
		dto.Level = "ORG_SUBTREE"
		dto.OrgId = scope.DataScope.OrgId
	case DataScopeProjectSet:
		dto.Level = "PROJECT_SET"
		dto.ProjectIds = append(dto.ProjectIds, scope.DataScope.ProjectIds...)
	case DataScopeMixed:
		dto.Level = "MIXED"
		dto.OrgId = scope.DataScope.OrgId
		dto.OrgIds = append(dto.OrgIds, scope.DataScope.OrgIds...)
		dto.ProjectIds = append(dto.ProjectIds, scope.DataScope.ProjectIds...)
	default:
		dto.Level = "PROJECT_SET"
	}
	return db.SetTycScopeFilterInCtx(ctx, dto), nil
}

// Sync 拉列表同步（组织/项目/用户/权限菜单）。软失败，不阻塞登录。
func (self *STycDriver) Sync(ctx context.Context) error {
	if self.client == nil {
		return nil
	}
	// 1) 组织（组织列表 qryOrganizationList，现场字段名以实际说明为准——示例传 orgName）
	orgs, err := self.client.ListOrganizations(ctx, self.conf.TenantId)
	if err != nil {
		return errors.Wrap(err, "sync tyc organizations: soft fail, alert")
	}
	if err := syncOrgTree(ctx, self.conf.TenantId, orgs, self.orgIdx); err != nil {
		return errors.Wrap(err, "syncOrgTree persist: soft fail, alert")
	}
	// 2) 项目（归属优先 sysBelongOrgId；缺失 fallback 挂域根 ORG-O000）
	projs, err := self.client.ListProjects(ctx, self.conf.TenantId, self.orgIdx)
	if err != nil {
		return errors.Wrap(err, "sync tyc projects: soft fail, alert")
	}
	if err := syncProjects(ctx, self.conf.TenantId, projs, self.orgIdx); err != nil {
		return errors.Wrap(err, "syncProjects persist: soft fail, alert")
	}
	// 3) （可选）用户列表同步
	// 4) （可选）705 权限/菜单同步
	return nil
}

// Probe 探测连通性（ValidateConfig 通过后调用）
func (self *STycDriver) Probe(ctx context.Context) error {
	if self.client == nil {
		return fmt.Errorf("nil tyc client")
	}
	return self.client.Probe(ctx)
}

// GetSsoRedirectUri/GetSsoCallbackUri 本驱动非重定向 SSO，不实现
func (self *STycDriver) GetSsoRedirectUri(ctx context.Context, callbackUrl, state string) (string, error) {
	return "", errors.Wrap(httperrors.ErrNotSupported, "tyc driver does not sso redirect")
}

func (self *STycDriver) GetSsoCallbackUri(callbackUrl string) string {
	return ""
}

// 暴露给登录 handler：把交换出来的 SystemUserDetail 变成 TycScope 草稿（最终写库在 handler 里）
func (self *STycDriver) BuildScopeDraft(ctx context.Context, detail *SystemUserDetail) (*TycScope, error) {
	return BuildTycScopeFromDetail(ctx, self.conf, detail, self.orgIdx)
}

// 暴露给 ScopeTTL 刷新：中间件异步刷新快照
func (self *STycDriver) RefreshScopeDraft(ctx context.Context, userId, sysUserCode string) (*TycScope, error) {
	return nil, nil // TODO(p1): 705 接口按 userId 刷新；占位，避免编译
}
