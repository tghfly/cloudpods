// Copyright 2019 Yunion
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

package tokens

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"yunion.io/x/jsonutils"
	"yunion.io/x/log"
	"yunion.io/x/pkg/errors"
	"yunion.io/x/pkg/util/s3auth"
	"yunion.io/x/sqlchemy"

	api "yunion.io/x/onecloud/pkg/apis/identity"
	notify_api "yunion.io/x/onecloud/pkg/apis/notify"
	"yunion.io/x/onecloud/pkg/cloudcommon/db"
	"yunion.io/x/onecloud/pkg/httperrors"
	"yunion.io/x/onecloud/pkg/keystone/driver"
	"yunion.io/x/onecloud/pkg/keystone/models"
	"yunion.io/x/onecloud/pkg/keystone/options"
	"yunion.io/x/onecloud/pkg/keystone/saml"
	"yunion.io/x/onecloud/pkg/mcclient"
	notify_modules "yunion.io/x/onecloud/pkg/mcclient/modules/notify"
	"yunion.io/x/onecloud/pkg/util/logclient"
)

func authUserByTokenV2(ctx context.Context, input mcclient.SAuthenticationInputV2) (*api.SUserExtended, error) {
	return authUserByToken(ctx, input.Auth.Token.Id)
}

func authUserByTokenV3(ctx context.Context, input mcclient.SAuthenticationInputV3) (*api.SUserExtended, error) {
	return authUserByToken(ctx, input.Auth.Identity.Token.Id)
}

func authUserByToken(ctx context.Context, tokenStr string) (*api.SUserExtended, error) {
	token, err := TokenStrDecode(ctx, tokenStr)
	if err != nil {
		return nil, errors.Wrap(err, "token.TokenStrDecode")
	}
	extUser, err := models.UserManager.FetchUserExtended(token.UserId, "", "", "")
	if err != nil {
		return nil, errors.Wrap(err, "FetchUserExtended")
	}
	extUser.AuditIds = []string{tokenStr}
	return extUser, nil
}

func authUserByPasswordV2(ctx context.Context, input mcclient.SAuthenticationInputV2) (*api.SUserExtended, error) {
	ident := mcclient.SAuthenticationIdentity{}
	ident.Methods = []string{api.AUTH_METHOD_PASSWORD}
	ident.Password.User.Name = input.Auth.PasswordCredentials.Username
	ident.Password.User.Password = input.Auth.PasswordCredentials.Password
	ident.Password.User.Domain.Id = api.DEFAULT_DOMAIN_ID
	return authUserByIdentity(ctx, ident, input.Auth.Context)
}

func authUserByIdentityV3(ctx context.Context, input mcclient.SAuthenticationInputV3) (*api.SUserExtended, error) {
	return authUserByIdentity(ctx, input.Auth.Identity, input.Auth.Context)
}

func authUserByIdentity(ctx context.Context, ident mcclient.SAuthenticationIdentity, authCtx mcclient.SAuthContext) (*api.SUserExtended, error) {
	usr, err := authUserByIdentityInternal(ctx, &ident)
	if err != nil {
		// log event
		ident.Password.User.Password = "***"
		log.Errorf("authenticate fail for %s reason: %s", jsonutils.Marshal(ident), err)
		user := logclient.NewSimpleObject(ident.Password.User.Id, ident.Password.User.Name, "user")
		token := GetDefaultAdminCredToken()
		token.(*mcclient.SSimpleToken).Context = authCtx
		logclient.AddActionLogWithContext(ctx, user, logclient.ACT_AUTHENTICATE, err, token, false)
	}
	return usr, err
}

func authUserByIdentityInternal(ctx context.Context, ident *mcclient.SAuthenticationIdentity) (*api.SUserExtended, error) {
	var idpId string

	if len(ident.Password.User.Name) == 0 && len(ident.Password.User.Id) == 0 && len(ident.Password.User.Domain.Id) == 0 && len(ident.Password.User.Domain.Name) == 0 {
		return nil, ErrEmptyAuth
	}
	if len(ident.Password.User.Name) > 0 && len(ident.Password.User.Id) == 0 && len(ident.Password.User.Domain.Id) == 0 && len(ident.Password.User.Domain.Name) == 0 {
		// no user domain specified, try to find user domain
		q := models.UserManager.Query().Equals("name", ident.Password.User.Name)
		usrCnt, err := q.CountWithError()
		if err != nil {
			return nil, errors.Wrap(err, "Query user by name")
		}
		if usrCnt > 1 {
			log.Errorf("find %d user with name %s", usrCnt, ident.Password.User.Name)
			return nil, sqlchemy.ErrDuplicateEntry
		} else if usrCnt == 0 {
			log.Errorf("find no user with name %s", ident.Password.User.Name)
			return nil, httperrors.ErrUserNotFound
		} else {
			// userCnt == 1
			usr := models.SUser{}
			usr.SetModelManager(models.UserManager, &usr)
			err := q.First(&usr)
			if err != nil {
				return nil, errors.Wrap(err, "Query user")
			}
			ident.Password.User.Domain.Id = usr.DomainId
			ident.Password.User.Id = usr.Id
		}
	}

	usrExt, err := models.UserManager.FetchUserExtended(ident.Password.User.Id, ident.Password.User.Name,
		ident.Password.User.Domain.Id, ident.Password.User.Domain.Name)
	if err != nil && errors.Cause(err) != httperrors.ErrUserNotFound {
		return nil, errors.Wrap(err, "UserManager.FetchUserExtended")
	}

	if err != nil {
		log.Errorf("no such user %s locally, query external IDP: %s", ident.Password.User.Name, err)
		// no such user locally, query domain idp
		domain, err := models.DomainManager.FetchDomain(ident.Password.User.Domain.Id, ident.Password.User.Domain.Name)
		if err != nil {
			if errors.Cause(err) != sql.ErrNoRows {
				return nil, errors.Wrap(err, "DomainManager.FetchDomain")
			} else {
				return nil, errors.Wrapf(httperrors.ErrUserNotFound, "domain %s", ident.Password.User.Domain.Name)
			}
		}
		mapping, err := models.IdmappingManager.FetchFirstEntity(domain.Id, api.IdMappingEntityDomain)
		if err != nil {
			if errors.Cause(err) != sql.ErrNoRows {
				return nil, errors.Wrap(err, "IdmappingManager.FetchEntity")
			} else {
				return nil, errors.Wrapf(httperrors.ErrUserNotFound, "idp")
			}
		}
		idpId = mapping.IdpId
	} else {
		// check enable
		if !usrExt.Enabled {
			if usrExt.IsLocal && usrExt.LocalFailedAuthCount > options.Options.PasswordErrorLockCount {
				// user locked
				return nil, httperrors.ErrUserLocked
			}
			// user disabled
			return nil, httperrors.ErrUserDisabled
		}
		// user is enabled, check expired time
		if !usrExt.ExpiredAt.IsZero() && usrExt.ExpiredAt.Before(time.Now()) {
			return nil, httperrors.ErrUserExpired
		}
		// user exists, query user's idp
		idps, err := models.IdentityProviderManager.FetchIdentityProvidersByUserId(usrExt.Id, api.PASSWORD_PROTECTED_IDPS)
		if err != nil {
			return nil, errors.Wrap(err, "IdentityProviderManager.FetchIdentityProvidersByUserId")
		}
		if len(idps) == 0 {
			idpId = api.DEFAULT_IDP_ID
		} else if len(idps) == 1 {
			idpId = idps[0].Id
		} else {
			return nil, sqlchemy.ErrDuplicateEntry
		}
	}

	if len(idpId) == 0 {
		idpId = api.DEFAULT_IDP_ID
	}
	idpObj, err := models.IdentityProviderManager.FetchById(idpId)
	if err != nil {
		return nil, errors.Wrap(err, "IdentityProviderManager.FetchById")
	}

	idp := idpObj.(*models.SIdentityProvider)

	if idp.Enabled.IsFalse() {
		return nil, errors.Wrap(httperrors.ErrInvalidIdpStatus, "idp disabled")
	}

	if idp.Status != api.IdentityDriverStatusConnected && idp.Status != api.IdentityDriverStatusDisconnected {
		return nil, errors.Wrapf(httperrors.ErrInvalidIdpStatus, "invalid idp status %s", idp.Status)
	}

	conf, err := models.GetConfigs(idp, true, nil, nil)
	if err != nil {
		return nil, errors.Wrap(err, "GetConfig")
	}

	backend, err := driver.GetDriver(idp.Driver, idp.Id, idp.Name, idp.Template, idp.TargetDomainId, conf)
	if err != nil {
		return nil, errors.Wrap(err, "driver.GetDriver")
	}

	usr, err := backend.Authenticate(ctx, *ident)
	if err != nil {
		return nil, errors.Wrap(err, "Authenticate")
	}

	if idp.Status == api.IdentityDriverStatusDisconnected {
		idp.MarkConnected(ctx, models.GetDefaultAdminCred())
	}
	return usr, nil
}

func authUserByCASV3(ctx context.Context, input mcclient.SAuthenticationInputV3) (*api.SUserExtended, error) {
	var idp *models.SIdentityProvider
	var err error
	if len(input.Auth.Identity.Id) > 0 {
		idp, err = models.IdentityProviderManager.FetchIdentityProviderById(input.Auth.Identity.Id)
		if err != nil {
			if errors.Cause(err) == sql.ErrNoRows {
				return nil, errors.Wrapf(httperrors.ErrResourceNotFound, "idp %s not found", input.Auth.Identity.Id)
			} else {
				return nil, errors.Wrap(err, "FetchIdentityProviderById")
			}
		}
	} else {
		idps, err := models.IdentityProviderManager.FetchEnabledProviders(api.IdentityDriverCAS)
		if err != nil {
			return nil, errors.Wrap(err, "models.fetchEnabledProviders")
		}
		if len(idps) == 0 {
			return nil, errors.Error("No cas identity provider")
		}
		if len(idps) > 1 {
			return nil, errors.Error("more than 1 cas identity providers?")
		}
		idp = &idps[0]
	}

	conf, err := models.GetConfigs(idp, true, nil, nil)
	if err != nil {
		return nil, errors.Wrap(err, "idp.GetConfig")
	}

	backend, err := driver.GetDriver(idp.Driver, idp.Id, idp.Name, idp.Template, idp.TargetDomainId, conf)
	if err != nil {
		return nil, errors.Wrap(err, "driver.GetDriver")
	}

	usr, err := backend.Authenticate(ctx, input.Auth.Identity)
	if err != nil {
		return nil, errors.Wrap(err, "Authenticate")
	}

	if idp.Status == api.IdentityDriverStatusDisconnected {
		idp.MarkConnected(ctx, models.GetDefaultAdminCred())
	}

	return usr, nil
}

func authUserBySAML(ctx context.Context, input mcclient.SAuthenticationInputV3) (*api.SUserExtended, error) {
	if !saml.IsSAMLEnabled() {
		return nil, errors.Wrap(httperrors.ErrNotSupported, "unsupported SAML backend")
	}

	idp, err := models.IdentityProviderManager.FetchIdentityProviderById(input.Auth.Identity.Id)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, errors.Wrapf(httperrors.ErrResourceNotFound, "idp %s not found", input.Auth.Identity.Id)
		} else {
			return nil, errors.Wrap(err, "FetchIdentityProviderById")
		}
	}

	conf, err := models.GetConfigs(idp, true, nil, nil)
	if err != nil {
		return nil, errors.Wrap(err, "idp.GetConfig")
	}

	backend, err := driver.GetDriver(idp.Driver, idp.Id, idp.Name, idp.Template, idp.TargetDomainId, conf)
	if err != nil {
		return nil, errors.Wrap(err, "driver.GetDriver")
	}

	usr, err := backend.Authenticate(ctx, input.Auth.Identity)
	if err != nil {
		return nil, errors.Wrap(err, "Authenticate")
	}

	if idp.Status == api.IdentityDriverStatusDisconnected {
		idp.MarkConnected(ctx, models.GetDefaultAdminCred())
	}

	return usr, nil
}

func authUserByOIDC(ctx context.Context, input mcclient.SAuthenticationInputV3) (*api.SUserExtended, error) {
	idp, err := models.IdentityProviderManager.FetchIdentityProviderById(input.Auth.Identity.Id)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, errors.Wrapf(httperrors.ErrResourceNotFound, "idp %s not found", input.Auth.Identity.Id)
		} else {
			return nil, errors.Wrap(err, "FetchIdentityProviderById")
		}
	}

	conf, err := models.GetConfigs(idp, true, nil, nil)
	if err != nil {
		return nil, errors.Wrap(err, "idp.GetConfig")
	}

	backend, err := driver.GetDriver(idp.Driver, idp.Id, idp.Name, idp.Template, idp.TargetDomainId, conf)
	if err != nil {
		return nil, errors.Wrap(err, "driver.GetDriver")
	}

	usr, err := backend.Authenticate(ctx, input.Auth.Identity)
	if err != nil {
		return nil, errors.Wrap(err, "Authenticate")
	}

	if idp.Status == api.IdentityDriverStatusDisconnected {
		idp.MarkConnected(ctx, models.GetDefaultAdminCred())
	}

	return usr, nil
}

func authUserByOAuth2(ctx context.Context, input mcclient.SAuthenticationInputV3) (*api.SUserExtended, error) {
	idp, err := models.IdentityProviderManager.FetchIdentityProviderById(input.Auth.Identity.Id)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, errors.Wrapf(httperrors.ErrResourceNotFound, "idp %s not found", input.Auth.Identity.Id)
		} else {
			return nil, errors.Wrap(err, "FetchIdentityProviderById")
		}
	}

	conf, err := models.GetConfigs(idp, true, nil, nil)
	if err != nil {
		return nil, errors.Wrap(err, "idp.GetConfig")
	}

	backend, err := driver.GetDriver(idp.Driver, idp.Id, idp.Name, idp.Template, idp.TargetDomainId, conf)
	if err != nil {
		return nil, errors.Wrap(err, "driver.GetDriver")
	}

	usr, err := backend.Authenticate(ctx, input.Auth.Identity)
	if err != nil {
		return nil, errors.Wrap(err, "Authenticate")
	}

	if idp.Status == api.IdentityDriverStatusDisconnected {
		idp.MarkConnected(ctx, models.GetDefaultAdminCred())
	}

	return usr, nil
}

func authUserByAccessKeyV3(ctx context.Context, input mcclient.SAuthenticationInputV3) (*api.SUserExtended, string, api.SAccessKeySecretInfo, error) {
	var aksk api.SAccessKeySecretInfo

	akskRequest, err := s3auth.Decode(input.Auth.Identity.AccessKeyRequest)
	if err != nil {
		return nil, "", aksk, errors.Wrap(err, "s3auth.Decode")
	}
	keyId := akskRequest.GetAccessKey()
	obj, err := models.CredentialManager.FetchById(keyId)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "", aksk, ErrInvalidAccessKeyId
		} else {
			return nil, "", aksk, errors.Wrap(err, "CredentialManager.FetchById")
		}
	}
	credential := obj.(*models.SCredential)
	if !credential.Enabled.IsTrue() {
		return nil, "", aksk, errors.Wrap(httperrors.ErrInvalidStatus, "Access Key disabled")
	}
	akBlob, err := credential.GetAccessKeySecret()
	if err != nil {
		return nil, "", aksk, errors.Wrap(err, "credential.GetAccessKeySecret")
	}
	if !akBlob.IsValid() {
		return nil, "", aksk, ErrExpiredAccessKey
	}
	aksk.AccessKey = keyId
	aksk.Secret = akBlob.Secret
	aksk.Expire = akBlob.Expire

	err = akskRequest.Verify(akBlob.Secret)
	if err != nil {
		return nil, "", aksk, errors.Wrap(err, "Verify")
	}
	usrExt, err := models.UserManager.FetchUserExtended(credential.UserId, "", "", "")
	if err != nil {
		return nil, "", aksk, errors.Wrap(err, "UserManager.FetchUserExtended")
	}

	usrExt.AuditIds = []string{keyId}

	return usrExt, credential.ProjectId, aksk, nil
}

func authUserByVerify(ctx context.Context, input mcclient.SAuthenticationInputV3) (*api.SUserExtended, error) {
	extUser, err := models.UserManager.FetchUserExtended(input.Auth.Identity.Verify.Uid, "", "", "")
	if err != nil {
		return nil, errors.Wrap(err, "FetchUserExtended")
	}
	s, err := GetDefaulAdminSession(ctx, "")
	if err != nil {
		return nil, errors.Wrap(err, "GetDefaultAdminSession")
	}
	verifyInput := notify_api.ReceiverVerifyInput{
		ContactType: input.Auth.Identity.Verify.ContactType,
		Token:       input.Auth.Identity.Verify.VerifyCode,
	}
	_, err = notify_modules.NotifyReceiver.PerformAction(s, extUser.Id, "verify", jsonutils.Marshal(verifyInput))
	if err != nil {
		return nil, errors.Wrap(err, "Verify")
	}

	extUser.AuditIds = []string{input.Auth.Identity.Verify.Uid}

	return extUser, nil
}

// ── TYC（tydic 智慧门户）认证 ───────────────────────────────────────────────
//
// 设计：
//   1) 本函数 = ExchangeToken + Sync + SaveScope，通过 driver.IIdentityBackend 接口 + 两个可选
//      鸭子接口（ISyncer / ITycScopeFlusher）完成，不直接 import tyc 包（避免耦合）。
//   2) body 语义（包装在 SAuthenticationInputV3.Auth.Identity 中）：
//        Identity.Id       = idp_id（必填；与 CAS 同口径）
//        Identity.Password.User.Password = tydic 门户 token（必填）
//        Identity.Password.User.Name     = sysUserCode（可选，hint 用）
//   3) 认证之后立刻同步组织/项目（软失败，只记日志），保证"第一次登录即可看到被授权项目"。
//   4) ITycScopeFlusher.PostAuthenticate 内部：BuildTycScopeFromDetail → SaveToUserExtra →
//      转 db.TycScopeFilterDTO 写 ctx（本函数调用链上的 TagFilter 会用到）。

// ISyncer driver.Sync() 原本就在 IIdentityBackend 里（driver.IIdentityBackend 有 Sync 方法）。
// 这里再显式列一遍，避免和 Authenticate 混淆。
type iDriverSyncer interface {
	Sync(ctx context.Context) error
}

// ITycScopeFlusher 由 tyc driver 可选实现（Go 鸭子类型：只要有方法就匹配，不需要 tyc import 这个接口）。
// 返回的 context 可能已经写入 TycScopeFilterDTO（供 TagFilter 行过滤）。
type iTycScopeFlusher interface {
	PostAuthenticate(ctx context.Context, usrExt *api.SUserExtended) (context.Context, error)
}

func authUserByTYC(ctx context.Context, input mcclient.SAuthenticationInputV3) (*api.SUserExtended, error) {
	var idp *models.SIdentityProvider
	var err error
	if len(input.Auth.Identity.Id) > 0 {
		idpObj, e2 := models.IdentityProviderManager.FetchIdentityProviderById(input.Auth.Identity.Id)
		if e2 != nil {
			if errors.Cause(e2) == sql.ErrNoRows {
				return nil, errors.Wrapf(httperrors.ErrResourceNotFound, "tyc idp %s not found", input.Auth.Identity.Id)
			}
			return nil, errors.Wrap(e2, "FetchIdentityProviderById")
		}
		idp = idpObj
	} else {
		// 没传 idp_id → 找 domain 下启用的第一个 tyc driver（SingletonInstance=true 在 class.go 已保证至多一份）
		idps, e2 := models.IdentityProviderManager.FetchEnabledProviders(api.IdentityDriverTyc)
		if e2 != nil {
			return nil, errors.Wrap(e2, "FetchEnabledProviders(tyc)")
		}
		if len(idps) == 0 {
			return nil, errors.Error("no enabled tyc identity provider")
		}
		if len(idps) > 1 {
			return nil, errors.Errorf("multiple tyc idps enabled (%d), please specify idp_id in body.identity.id", len(idps))
		}
		idp = &idps[0]
	}
	if idp.Driver != api.IdentityDriverTyc {
		return nil, errors.Wrapf(httperrors.ErrInputParameter, "idp %s driver=%s, expected %s", idp.Id, idp.Driver, api.IdentityDriverTyc)
	}
	if idp.Enabled.IsFalse() {
		return nil, errors.Wrap(httperrors.ErrInvalidIdpStatus, "tyc idp disabled")
	}

	conf, err := models.GetConfigs(idp, true, nil, nil)
	if err != nil {
		return nil, errors.Wrap(err, "idp.GetConfigs")
	}
	backend, err := driver.GetDriver(idp.Driver, idp.Id, idp.Name, idp.Template, idp.TargetDomainId, conf)
	if err != nil {
		return nil, errors.Wrap(err, "driver.GetDriver(tyc)")
	}
	// 把 tydic token 放在 ident.Password.User.Password 字段（和 CAS/SAML 统一约定：非 password 认证也复用这个结构传 credential）
	ident := input.Auth.Identity
	if len(ident.Methods) == 0 {
		ident.Methods = []string{api.AUTH_METHOD_TYC}
	}
	usrExt, err := backend.Authenticate(ctx, ident)
	if err != nil {
		return nil, errors.Wrap(err, "tyc backend.Authenticate (ExchangeToken)")
	}
	if idp.Status == api.IdentityDriverStatusDisconnected {
		idp.MarkConnected(ctx, models.GetDefaultAdminCred())
	}

	// Step 2: 同步组织/项目（幂等；软失败，只告警不阻断登录——第一次登录至少能拿到 unscoped token）
	if syncer, ok := backend.(iDriverSyncer); ok {
		if e := syncer.Sync(ctx); e != nil {
			log.Errorf("[tyc auth] backend.Sync soft fail (continue login): %v", e)
		}
	}

	// Step 3: 如果 backend 实现了 ITycScopeFlusher → 落 TycScope 到 SUser.Extra + 写 DTO 到 ctx。
	//         非 TYC 后端（理论不会走到这里）直接跳过。
	if flusher, ok := backend.(iTycScopeFlusher); ok {
		if ctx2, e2 := flusher.PostAuthenticate(ctx, usrExt); e2 == nil && ctx2 != nil {
			ctx = ctx2
		} else if e2 != nil {
			log.Errorf("[tyc auth] PostAuthenticate (scope flush) soft fail: %v", e2)
		}
	} else {
		// 兜底：如果没有实现 ITycScopeFlusher，至少从 usrExt.Extra 里拼一个最小 DTO 给 TagFilter。
		// 这样就算 Phase 0 没连 705 dataScope 接口，也能用 PROJECT_SET 回退口径生效。
		dto := tycBuildMinimalDTOFromExt(usrExt)
		if dto != nil {
			ctx = db.SetTycScopeFilterInCtx(ctx, dto)
		}
	}
	return usrExt, nil
}

// tycBuildMinimalDTOFromExt 兜底：PostAuthenticate 未实现时，通过 usrExt.Id → 查 models.SUser → 取 Extra → 拼 DTO。
// （api.SUserExtended 没有 Extra 字段，Extra 存在于 models.SUser）
func tycBuildMinimalDTOFromExt(usrExt *api.SUserExtended) *db.TycScopeFilterDTO {
	if usrExt == nil || len(usrExt.Id) == 0 {
		return nil
	}
	usr, err := models.UserManager.FetchById(usrExt.Id)
	if err != nil {
		return nil
	}
	suser, _ := usr.(*models.SUser)
	if suser == nil || suser.Extra == nil {
		return nil
	}
	// 从 SUser.Extra 取 tyc_scope 先看有没有（如果登录阶段已经写了，这里直接用）
	if v, e2 := suser.Extra.GetString("tyc_scope"); e2 == nil && len(v) > 0 {
		// 有 tyc_scope JSON → 反解为完整 4 档 DTO
		type tycScopeLike struct {
			TenantId  string `json:"tenantId"`
			DataScope struct {
				Level      string   `json:"level"`
				OrgId      string   `json:"orgId,omitempty"`
				OrgIds     []string `json:"orgIds,omitempty"`
				ProjectIds []string `json:"projectIds,omitempty"`
			} `json:"dataScope"`
		}
		var ts tycScopeLike
		if je := json.Unmarshal([]byte(v), &ts); je == nil && len(ts.DataScope.Level) > 0 {
			dto := &db.TycScopeFilterDTO{
				Level:      ts.DataScope.Level,
				DomainId:   ts.TenantId,
				OrgId:      ts.DataScope.OrgId,
				OrgIds:     ts.DataScope.OrgIds,
				ProjectIds: ts.DataScope.ProjectIds,
			}
			return dto
		}
	}
	mp := map[string]interface{}{}
	if e2 := suser.Extra.Unmarshal(&mp); e2 != nil {
		return nil
	}
	str := func(k string) string {
		v, _ := mp[k].(string)
		return v
	}
	tenantId := str("tenant_id")
	proj := str("project_id")
	// project_id_list_tyc 是 []string 或 []interface{}
	var pids []string
	if raw, ok2 := mp["project_id_list_tyc"].([]string); ok2 {
		pids = raw
	} else if arr, ok3 := mp["project_id_list_tyc"].([]interface{}); ok3 {
		for _, x := range arr {
			if s, ok4 := x.(string); ok4 && s != "" {
				pids = append(pids, s)
			}
		}
	}
	if proj != "" {
		pids = append([]string{proj}, pids...)
	}
	// districtAdm=1100 → DOMAIN_ALL，否则 PROJECT_SET
	level := "PROJECT_SET"
	if v, ok5 := mp["district_adm"].(float64); ok5 && int(v) == 1100 {
		level = "DOMAIN_ALL"
	}
	if v, ok5 := mp["district_adm"].(int); ok5 && v == 1100 {
		level = "DOMAIN_ALL"
	}
	return &db.TycScopeFilterDTO{
		Level:      level,
		DomainId:   tenantId,
		ProjectIds: pids,
	}
}

// +onecloud:swagger-gen-route-method=POST
// +onecloud:swagger-gen-route-path=/v3/auth/tokens
// +onecloud:swagger-gen-route-tag=authentication
// +onecloud:swagger-gen-param-body-index=1
// +onecloud:swagger-gen-resp-index=0
// +onecloud:swagger-gen-resp-header=X-Subject-Token
// +onecloud:swagger-gen-resp-header=验证成功的keystone V3 token

// keystone v3认证API
func AuthenticateV3(ctx context.Context, input mcclient.SAuthenticationInputV3) (*mcclient.TokenCredentialV3, error) {
	var akskInfo api.SAccessKeySecretInfo
	var user *api.SUserExtended
	var err error
	if len(input.Auth.Identity.Methods) != 1 {
		return nil, ErrInvalidAuthMethod
	}
	method := input.Auth.Identity.Methods[0]
	switch method {
	case api.AUTH_METHOD_TOKEN:
		// auth by token
		user, err = authUserByTokenV3(ctx, input)
		if err != nil {
			return nil, errors.Wrap(err, "authUserByTokenV3")
		}
	case api.AUTH_METHOD_AKSK:
		// auth by aksk
		user, input.Auth.Scope.Project.Id, akskInfo, err = authUserByAccessKeyV3(ctx, input)
		if err != nil {
			return nil, errors.Wrap(err, "authUserByAccessKeyV3")
		}
	case api.AUTH_METHOD_CAS:
		// auth by apereo CAS
		user, err = authUserByCASV3(ctx, input)
		if err != nil {
			return nil, errors.Wrap(err, "authUserByCASV3")
		}
	case api.AUTH_METHOD_SAML:
		// auth by SAML 2.0 IDP, keystone acts as a SAML SP
		user, err = authUserBySAML(ctx, input)
		if err != nil {
			return nil, errors.Wrap(err, "authUserBySAML")
		}
	case api.AUTH_METHOD_OIDC:
		// auth by OpenID Connect, keystone acts as an OpenID Connect client
		user, err = authUserByOIDC(ctx, input)
		if err != nil {
			return nil, errors.Wrap(err, "authUserByOIDC")
		}
	case api.AUTH_METHOD_OAuth2:
		// auth by customized OAuth2.0 provider, keystone acts as an OAuth2.0 app
		user, err = authUserByOAuth2(ctx, input)
		if err != nil {
			return nil, errors.Wrap(err, "authUserByOAuth2")
		}
	case api.AUTH_METHOD_VERIFY:
		user, err = authUserByVerify(ctx, input)
		if err != nil {
			return nil, errors.Wrap(err, "authUserByVerify")
		}
	case api.AUTH_METHOD_ASSUME:
		user, err = authUserByAssume(ctx, input)
		if err != nil {
			return nil, errors.Wrap(err, "authUserByAssume")
		}
	case api.AUTH_METHOD_TYC:
		// auth by tydic 智慧门户 token（body.idp_id + body.token → cloudpods unscoped/scoped token）
		// authUserByTYC 内部：ExchangeToken → Sync → Save TycScope → 写 ctx(TagFilter DTO)
		user, err = authUserByTYC(ctx, input)
		if err != nil {
			return nil, errors.Wrap(err, "authUserByTYC")
		}
	default:
		// auth by other methods, e.g. password , etc...
		user, err = authUserByIdentityV3(ctx, input)
		if err != nil {
			return nil, err
		}
	}

	// user not found
	if user == nil {
		return nil, ErrUserNotFound
	}
	// user is not enabled
	if !user.Enabled {
		return nil, ErrUserDisabled
	}
	// user is expired
	if !user.ExpiredAt.IsZero() && user.ExpiredAt.Before(time.Now()) {
		return nil, httperrors.ErrUserExpired
	}

	if !user.DomainEnabled {
		return nil, ErrDomainDisabled
	}

	token := SAuthToken{}
	token.UserId = user.Id
	token.Method = method
	token.AuditIds = user.AuditIds
	now := time.Now().UTC()
	token.ExpiresAt = now.Add(time.Duration(options.Options.TokenExpirationSeconds) * time.Second)
	if !user.ExpiredAt.IsZero() && user.ExpiredAt.Before(token.ExpiresAt) {
		token.ExpiresAt = user.ExpiredAt
	}
	token.Context = input.Auth.Context

	if len(input.Auth.Scope.Project.Id) == 0 && len(input.Auth.Scope.Project.Name) == 0 && len(input.Auth.Scope.Domain.Id) == 0 && len(input.Auth.Scope.Domain.Name) == 0 {
		// unscoped auth
		return token.getTokenV3(ctx, user, nil, nil, akskInfo)
	}
	var projExt *models.SProjectExtended
	var domain *models.SDomain
	if len(input.Auth.Scope.Project.Id) > 0 || len(input.Auth.Scope.Project.Name) > 0 {
		project, err := models.ProjectManager.FetchProject(
			input.Auth.Scope.Project.Id,
			input.Auth.Scope.Project.Name,
			input.Auth.Scope.Project.Domain.Id,
			input.Auth.Scope.Project.Domain.Name,
		)
		if err != nil {
			return nil, errors.Wrap(err, "ProjectManager.FetchProject")
		}
		// if project.Enabled.IsFalse() {
		// 	return nil, ErrProjectDisabled
		// }
		projExt, err = project.FetchExtend()
		if err != nil {
			return nil, errors.Wrap(err, "project.FetchExtend")
		}
		token.ProjectId = project.Id
	} else {
		domain, err = models.DomainManager.FetchDomain(input.Auth.Scope.Domain.Id,
			input.Auth.Scope.Domain.Name)
		if err != nil {
			return nil, errors.Wrap(err, "DomainManager.FetchDomain")
		}
		if domain.Enabled.IsFalse() {
			return nil, ErrDomainDisabled
		}
		token.DomainId = domain.Id
	}
	tokenV3, err := token.getTokenV3(ctx, user, projExt, domain, akskInfo)
	if err != nil {
		return nil, errors.Wrap(err, "getTokenV3")
	}

	return tokenV3, nil
}

type SAuthenticateV2ResponseBody struct {
	Access mcclient.TokenCredentialV2 `json:"access"`
}

// +onecloud:swagger-gen-route-method=POST
// +onecloud:swagger-gen-route-path=/v2.0/tokens
// +onecloud:swagger-gen-route-tag=authentication
// +onecloud:swagger-gen-param-body-index=1
// +onecloud:swagger-gen-resp-index=0

// keystone v2 认证接口，通过用户名/密码或者 token 认证
func AuthenticateV2(ctx context.Context, input mcclient.SAuthenticationInputV2) (*SAuthenticateV2ResponseBody, error) {
	token, err := _authenticateV2(ctx, input)
	if err != nil {
		return nil, errors.Wrap(err, "_authenticateV2")
	}
	body := SAuthenticateV2ResponseBody{
		Access: *token,
	}
	return &body, nil
}

func _authenticateV2(ctx context.Context, input mcclient.SAuthenticationInputV2) (*mcclient.TokenCredentialV2, error) {
	var user *api.SUserExtended
	var err error
	var method string
	if len(input.Auth.Token.Id) > 0 {
		// auth by token
		user, err = authUserByTokenV2(ctx, input)
		if err != nil {
			return nil, errors.Wrap(err, "authUserByTokenV2")
		}
		method = api.AUTH_METHOD_TOKEN
	} else {
		// auth by password
		user, err = authUserByPasswordV2(ctx, input)
		if err != nil {
			return nil, errors.Wrap(err, "authUserByPasswordV2")
		}
		method = api.AUTH_METHOD_PASSWORD
	}
	// user not found
	if user == nil {
		return nil, ErrUserNotFound
	}
	// user is not enabled
	if !user.Enabled {
		return nil, ErrUserDisabled
	}

	if !user.DomainEnabled {
		return nil, ErrDomainDisabled
	}

	token := SAuthToken{}
	token.UserId = user.Id
	token.Method = method
	token.AuditIds = user.AuditIds
	now := time.Now().UTC()
	token.ExpiresAt = now.Add(time.Duration(options.Options.TokenExpirationSeconds) * time.Second)
	token.Context = input.Auth.Context

	if len(input.Auth.TenantId) == 0 && len(input.Auth.TenantName) == 0 {
		// unscoped auth
		return token.getTokenV2(ctx, user, nil)
	}
	project, err := models.ProjectManager.FetchProject(
		input.Auth.TenantId,
		input.Auth.TenantName,
		api.DEFAULT_DOMAIN_ID, "")
	if err != nil {
		return nil, errors.Wrap(err, "ProjectManager.FetchProject")
	}
	// if project.Enabled.IsFalse() {
	// 	return nil, ErrProjectDisabled
	// }
	token.ProjectId = project.Id
	projExt, err := project.FetchExtend()
	if err != nil {
		return nil, errors.Wrap(err, "project.FetchExtend")
	}

	tokenV2, err := token.getTokenV2(ctx, user, projExt)
	if err != nil {
		return nil, errors.Wrap(err, "getTokenV2")
	}

	return tokenV2, nil
}
