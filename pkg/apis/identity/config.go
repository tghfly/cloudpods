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

package identity

import "yunion.io/x/jsonutils"

const (
	QueryScopeOne = "one"
	QUeryScopeSub = "sub"
)

type TConfigs map[string]map[string]jsonutils.JSONObject

type SLDAPIdpConfigBaseOptions struct {
	Url      string `json:"url,omitempty" help:"LDAP server URL" required:"true"`
	Suffix   string `json:"suffix,omitempty" required:"true"`
	User     string `json:"user,omitempty" required:"true"`
	Password string `json:"password,omitempty" required:"true"`

	DisableUserOnImport bool `json:"disable_user_on_import"`
}

type SLDAPIdpConfigSingleDomainOptions struct {
	SLDAPIdpConfigBaseOptions

	UserTreeDN  string `json:"user_tree_dn,omitempty" help:"Base user tree distinguished name" required:"true"`
	GroupTreeDN string `json:"group_tree_dn,omitempty" help:"Base group tree distinguished name" required:"true"`
}

type SLDAPIdpConfigMultiDomainOptions struct {
	SLDAPIdpConfigBaseOptions

	DomainTreeDN string `json:"domain_tree_dn,omitempty" help:"Base domain tree distinguished name" required:"true"`
}

type SLDAPIdpConfigOptions struct {
	Url        string `json:"url,omitempty" help:"LDAP server URL" required:"true"`
	Suffix     string `json:"suffix,omitempty" required:"true"`
	QueryScope string `json:"query_scope,omitempty" help:"Query scope" choices:"one|sub"`

	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`

	DisableUserOnImport bool `json:"disable_user_on_import"`

	DomainTreeDN        string `json:"domain_tree_dn,omitempty" help:"Domain tree root node dn(distinguished name)"`
	DomainFilter        string `json:"domain_filter,omitempty"`
	DomainObjectclass   string `json:"domain_objectclass,omitempty"`
	DomainIdAttribute   string `json:"domain_id_attribute,omitempty"`
	DomainNameAttribute string `json:"domain_name_attribute,omitempty"`
	DomainQueryScope    string `json:"domain_query_scope,omitempty" help:"Query scope" choices:"one|sub"`

	UserTreeDN              string   `json:"user_tree_dn,omitempty" help:"User tree distinguished name"`
	UserFilter              string   `json:"user_filter,omitempty"`
	UserObjectclass         string   `json:"user_objectclass,omitempty"`
	UserIdAttribute         string   `json:"user_id_attribute,omitempty"`
	UserNameAttribute       string   `json:"user_name_attribute,omitempty"`
	UserEnabledAttribute    string   `json:"user_enabled_attribute,omitempty"`
	UserEnabledMask         int64    `json:"user_enabled_mask,allowzero" default:"-1"`
	UserEnabledDefault      string   `json:"user_enabled_default,omitempty"`
	UserEnabledInvert       bool     `json:"user_enabled_invert,allowfalse"`
	UserAdditionalAttribute []string `json:"user_additional_attribute_mapping,omitempty" token:"user_additional_attribute"`
	UserQueryScope          string   `json:"user_query_scope,omitempty" help:"Query scope" choices:"one|sub"`

	GroupTreeDN          string `json:"group_tree_dn,omitempty" help:"Group tree distinguished name"`
	GroupFilter          string `json:"group_filter,omitempty"`
	GroupObjectclass     string `json:"group_objectclass,omitempty"`
	GroupIdAttribute     string `json:"group_id_attribute,omitempty"`
	GroupNameAttribute   string `json:"group_name_attribute,omitempty"`
	GroupMemberAttribute string `json:"group_member_attribute,omitempty"`
	GroupMembersAreIds   bool   `json:"group_members_are_ids,allowfalse"`
	GroupQueryScope      string `json:"group_query_scope,omitempty" help:"Query scope" choices:"one|sub"`
}

// STycIdpConfigOptions tydic 智慧门户驱动配置（v2：同步解耦 + 双管道数据权限）。
// 敏感字段（userinfo_secret/callback_secret/rsa_private_key_pem）走 sensitive_config，
// 其余非敏感字段走 whitelisted_config / options / 环境变量（双轨制）。
type STycIdpConfigOptions struct {
	BaseUrl                string `json:"base_url" help:"tydic 智慧门户 base URL，例如 https://tydc.example.com" required:"true"`
	AppKey                 string `json:"app_key" help:"tydic 集团主数据 appKey（TcpCont.appKey）" required:"true"`
	DstSysId               string `json:"dst_sys_id" help:"tydic dstSysId（目标系统编码）" required:"true"`
	AppId                  string `json:"app_id,omitempty" help:"tydic 归属系统编码（705…权限接口 svcCont.appId 必传；其他接口可留空）"`
	TenantId               string `json:"tenant_id,omitempty" help:"默认租户 ID，用于 qryOrganizationList / qryProjectList 过滤"`
	EnableRSA              bool   `json:"enable_rsa,allowfalse" help:"是否启用 RSA 二次签名；false=仅 MD5，按现场开关调整"`
	RSAPrivateKeyPEM       string `json:"rsa_private_key_pem,omitempty" help:"RSA 私钥 PEM（启用 RSA 时必填）" token:"rsa_private_key_pem"`
	RequestTimeoutSeconds  int    `json:"request_timeout_seconds,allowzero" default:"15" help:"tydic HTTP 请求超时（秒）"`
	UserInfoSecret         string `json:"userinfo_secret,omitempty" help:"MD5 签名 SecretKey：/sso/getUserInfoByToken、doService 列表接口（默认 AD67EA2F3BE6E5AD）" token:"userinfo_secret"`
	CallbackSecret         string `json:"callback_secret,omitempty" help:"MD5 签名 SecretKey：/sso/sync 退出回调（默认 RT4QRDK3FW2CE61）" token:"callback_secret"`
	ScopeSnapshotTTLSeconds int   `json:"scope_snapshot_ttl_seconds,allowzero" default:"60" help:"TycScope 快照 TTL（秒）；webhook 模式下可写 0 强制立即刷新"`
}

const (
	IdpTemplateMSSingleDomain       = "msad_one_domain"
	IdpTemplateMSMultiDomain        = "msad_multi_domain"
	IdpTemplateOpenLDAPSingleDomain = "openldap_one_domain"

	IdpTemplateSAMLTest    = "samltest_saml"
	IdpTemplateAzureADSAML = "azure_ad_saml"

	IdpTemplateDex         = "dex_oidc"
	IdpTemplateGithub      = "github_oidc"
	IdpTemplateAzureOAuth2 = "azure_oidc"
	IdpTemplateGoogle      = "google_oidc"

	IdpTemplateAlipay   = "alipay_oauth2"
	IdpTemplateWechat   = "wechat_oauth2"
	IdpTemplateDingtalk = "dingtalk_oauth2"
	IdpTemplateFeishu   = "feishu_oauth2"
	IdpTemplateQywechat = "qywechat_oauth2"
	IdpTemplateBingoIAM = "bingoiam_oauth2"

	IdpTemplateTyc_Driver = IdpTemplateTyc // consts.go 已声明 IdpTemplateTyc="tyc_default"
)

var (
	IdpTemplateDriver = map[string]string{
		IdpTemplateMSSingleDomain:       IdentityDriverLDAP,
		IdpTemplateMSMultiDomain:        IdentityDriverLDAP,
		IdpTemplateOpenLDAPSingleDomain: IdentityDriverLDAP,

		IdpTemplateSAMLTest:    IdentityDriverSAML,
		IdpTemplateAzureADSAML: IdentityDriverSAML,

		IdpTemplateDex:         IdentityDriverOIDC,
		IdpTemplateGithub:      IdentityDriverOIDC,
		IdpTemplateAzureOAuth2: IdentityDriverOIDC,
		IdpTemplateGoogle:      IdentityDriverOIDC,

		IdpTemplateAlipay:   IdentityDriverOAuth2,
		IdpTemplateFeishu:   IdentityDriverOAuth2,
		IdpTemplateDingtalk: IdentityDriverOAuth2,
		IdpTemplateWechat:   IdentityDriverOAuth2,
		IdpTemplateQywechat: IdentityDriverOAuth2,
		IdpTemplateBingoIAM: IdentityDriverOAuth2,

		IdpTemplateTyc: IdentityDriverTyc,
	}
)

type PerformConfigInput struct {
	// 更新配置的方式
	// example: update
	//
	// | action  |  含义                                         |
	// |---------|-----------------------------------------------|
	// | update  | 增量更新配置                                  |
	// | remove  | 删除指定配置                                  |
	// | replace | 全量替换配置，如果action为空，则默认为replace |
	//
	Action string `json:"action"`

	// 配置信息
	Config TConfigs `json:"config"`
}
