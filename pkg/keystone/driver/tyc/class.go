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

	"yunion.io/x/jsonutils"
	"yunion.io/x/pkg/errors"

	api "yunion.io/x/onecloud/pkg/apis/identity"
	"yunion.io/x/onecloud/pkg/httperrors"
	"yunion.io/x/onecloud/pkg/keystone/driver"
	"yunion.io/x/onecloud/pkg/keystone/models"
	"yunion.io/x/onecloud/pkg/mcclient"
)

// STycDriverClass 注册 tydic 驱动类到 driver 工厂。
//
// 语义：IsSso=false（不出现在前端 SSO 按钮列表——统一门户携带 token 进来，不是 cloudpods 发起重定向）；
// SyncMethod=OnAuth（登录入口触发同步，两者不冲突）。
type STycDriverClass struct{}

func (self *STycDriverClass) IsSso() bool {
	return false
}

func (self *STycDriverClass) ForceSyncUser() bool {
	return true
}

func (self *STycDriverClass) GetDefaultIconUri(tmpName string) string {
	// tydic 智慧门户的默认占位图标，不对外开放 SSO 重定向，仅后台显示
	return "https://www.yunion.cn/icons/tyc-portal.svg"
}

func (self *STycDriverClass) SingletonInstance() bool {
	return true
}

func (self *STycDriverClass) SyncMethod() string {
	return api.IdentityProviderSyncOnAuth
}

func (self *STycDriverClass) Name() string {
	return api.IdentityDriverTyc
}

func (self *STycDriverClass) NewDriver(idpId, idpName, template, targetDomainId string, conf api.TConfigs) (driver.IIdentityBackend, error) {
	return NewTycDriver(idpId, idpName, template, targetDomainId, conf)
}

func (self *STycDriverClass) ValidateConfig(
	ctx context.Context,
	userCred mcclient.TokenCredential,
	template string,
	tconf api.TConfigs,
	idpId, domainId string,
) (api.TConfigs, error) {
	conf := api.STycIdpConfigOptions{}
	confJson := jsonutils.Marshal(tconf[api.IdentityDriverTyc])
	if err := confJson.Unmarshal(&conf); err != nil {
		return tconf, errors.Wrap(err, "unmarshal tyc config")
	}
	if len(conf.BaseUrl) == 0 {
		return tconf, errors.Wrap(httperrors.ErrInputParameter, "empty tyc.base_url")
	}
	if len(conf.AppKey) == 0 {
		return tconf, errors.Wrap(httperrors.ErrInputParameter, "empty tyc.app_key")
	}
	if len(conf.DstSysId) == 0 {
		return tconf, errors.Wrap(httperrors.ErrInputParameter, "empty tyc.dst_sys_id")
	}
	// AppId 仅 705 权限接口必填，单做登录可空，故不做强校验
	if len(conf.UserInfoSecret) == 0 {
		return tconf, errors.Wrap(httperrors.ErrInputParameter, "empty tyc.userinfo_secret (md5 secret)")
	}
	if len(conf.CallbackSecret) == 0 {
		return tconf, errors.Wrap(httperrors.ErrInputParameter, "empty tyc.callback_secret (md5 secret for sso sync)")
	}
	// 唯一性：app_key × dst_sys_id 在一个 idp/domain 中只允许一份
	unique, err := models.IdentityProviderManager.CheckUniqueness(
		idpId, domainId,
		api.IdentityDriverTyc, template,
		api.IdentityDriverTyc, "app_key", jsonutils.NewString(conf.AppKey),
	)
	if err != nil {
		return tconf, errors.Wrap(err, "IdentityProviderManager.CheckUniqueness")
	}
	if !unique {
		return tconf, errors.Wrapf(httperrors.ErrDuplicateResource, "app_key %s already registered for tyc idp", conf.AppKey)
	}
	nconf := make(map[string]jsonutils.JSONObject)
	if err := confJson.Unmarshal(&nconf); err != nil {
		return tconf, errors.Wrap(err, "Unmarshal old tyc config map")
	}
	if err := jsonutils.Marshal(conf).Unmarshal(&nconf); err != nil {
		return tconf, errors.Wrap(err, "Unmarshal normalized tyc config")
	}
	tconf[api.IdentityDriverTyc] = nconf
	return tconf, nil
}

func init() {
	driver.RegisterDriverClass(&STycDriverClass{})
}
