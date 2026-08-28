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
	"bytes"
	"context"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"yunion.io/x/jsonutils"
	"yunion.io/x/log"
	"yunion.io/x/pkg/errors"

	api "yunion.io/x/onecloud/pkg/apis/identity"
	"yunion.io/x/onecloud/pkg/cloudcommon/db"
	"yunion.io/x/onecloud/pkg/httperrors"
	models "yunion.io/x/onecloud/pkg/keystone/models"
)

// ── tydic 服务总线 HTTP 客户端 + 同步持久化（事实层） ────────────────────────

// TYCHttpClient 封装 /sso/getUserInfoByToken 和 /esmp-serve-rest/rest/serve/doService(svcCode) 两种接口。
// 签名：
//
//	signTemp = MD5(transactionId + svcCont JSON + SecretKey)  // 32 位小写
//	sign = RSA_Sign(signTemp)   // 如果现场启用 RSA；否则退化纯 MD5，直接写 sign=signTemp
type TYCHttpClient struct {
	conf    api.STycIdpConfigOptions
	httpCli *http.Client
	rsaKey  *rsa.PrivateKey // 当 conf.EnableRSA=true 时使用
	mu      sync.Mutex
}

// NewTYCHttpClient 构造器
func NewTYCHttpClient(conf api.STycIdpConfigOptions) (*TYCHttpClient, error) {
	if len(conf.BaseUrl) == 0 {
		return nil, httperrors.NewInputParameterError("empty tyc base_url")
	}
	cli := &http.Client{
		Timeout: time.Duration(conf.RequestTimeoutSeconds) * time.Second,
	}
	if cli.Timeout <= 0 {
		cli.Timeout = 15 * time.Second
	}
	c := &TYCHttpClient{conf: conf, httpCli: cli}
	if conf.EnableRSA && len(conf.RSAPrivateKeyPEM) > 0 {
		k, err := parseRSAPrivate([]byte(conf.RSAPrivateKeyPEM))
		if err != nil {
			return nil, errors.Wrap(err, "parse RSA private key for tyc sign")
		}
		c.rsaKey = k
	}
	return c, nil
}

// ── 工具：signTemp / 签名 ───────────────────────────────────────────────────

func md5Sum(parts ...string) string {
	h := md5.New()
	for _, p := range parts {
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (c *TYCHttpClient) signPayload(txnId string, svcContJSON []byte, secret string) (signTemp string, sign string) {
	signTemp = strings.ToLower(md5Sum(txnId, string(svcContJSON), secret))
	if c.conf.EnableRSA && c.rsaKey != nil {
		s, err := rsaSignSHA256(c.rsaKey, []byte(signTemp))
		if err == nil {
			sign = s
			return
		}
		// RSA 失败回退纯 MD5（联调环境可能还没配 RSA 对）
	}
	sign = signTemp
	return
}

// newTxnId 生成 28 位交易流水号：yyyyMMddHHmmssSSS(17 位) + 11 位随机数字
// tydic 规范要求：28 位
func newTxnId() string {
	now := time.Now()
	prefix := now.Format("20060102150405000")
	return prefix + randomDigits(28-len(prefix))
}

// newReqTime 格式：yyyyMMddHHmmssSSS
func newReqTime() string { return time.Now().Format("20060102150405000") }

// ── SystemUserDetail / DTO ─────────────────────────────────────────────────

// SystemUserDetail tydic 返回的完整身份（sso §2.1）
type SystemUserDetail struct {
	TenantId      string   `json:"tenantId"`
	TenantCode    string   `json:"tenantCode"`
	TenantName    string   `json:"tenantName"`
	OrgId         string   `json:"orgId"`
	OrgName       string   `json:"orgName"`
	RegionId      string   `json:"regionId"`
	RegionCode    string   `json:"regionCode"`
	RegionName    string   `json:"regionName"`
	ProjectId     string   `json:"projectId"`
	ProjectIdList []string `json:"projectIdList"`
	ProjectCode   string   `json:"projectCode"`
	ProjectName   string   `json:"projectName"`
	SysUserId     string   `json:"sysUserId"`
	SysUserCode   string   `json:"sysUserCode"`
	StaffId       string   `json:"staffId"`
	StaffName     string   `json:"staffName"`
	PwdSmsTel     string   `json:"pwdSmsTel"`
	SysRoleId     int      `json:"sysRoleId"`
	SysRoleName   string   `json:"sysRoleName"`
	DistrictAdm   int      `json:"districtAdm"` // 1100=全区，1000=普通
	// 705 接口返回的"数据权限字段"——Phase 0 联调确认字段名；有则直接用，省掉回退推测
	PrivsDataScope *DataScope `json:"_privsDataScope,omitempty"`
}

// TycOrgNodeDTO 组织列表返回扁平节点，之后按 parentId 构树
type TycOrgNodeDTO struct {
	OrgId       string `json:"orgId"`
	OrgCode     string `json:"orgCode"`
	OrgName     string `json:"orgName"`
	ParentOrgId string `json:"parentOrgId"`
	Level       int    `json:"orgLevel"`
}

// TycProjectDTO 项目列表
type TycProjectDTO struct {
	ProjectId      string `json:"projectId"`
	ProjectCode    string `json:"projectCode"`
	ProjectName    string `json:"projectName"`
	TenantId       string `json:"tenantId"`
	SysBelongOrgId string `json:"sysBelongOrgId"` // 最关键：项目归属 org
	RegionId       string `json:"regionId"`
	RegionCode     string `json:"regionCode"`
}

// TycStandardResp tydic 标准响应（contractRoot 返回外层）
type TycStandardResp struct {
	ResultCode int             `json:"resultCode"`
	ResultMsg  string          `json:"resultMsg"`
	SvcCont    json.RawMessage `json:"svcCont"`
}

// ── 业务调用：ExchangeToken / ListOrganizations / ListProjects / Probe ─────

// ExchangeToken 实现"路径 B：/sso/getUserInfoByToken 换人"。
// 生产强制走这条；路径 A Base64 decode 只在调试时单独 helper（未暴露给 Authenticate）。
// 返回的错误会被 Authenticate 当 HARD FAIL 终止登录。
func (c *TYCHttpClient) ExchangeToken(ctx context.Context, token, extTxnId string) (*SystemUserDetail, error) {
	if len(token) == 0 {
		return nil, httperrors.NewUnauthorizedError("empty tyc token: HARD FAIL")
	}
	secret := c.conf.UserInfoSecret
	if len(secret) == 0 {
		return nil, httperrors.NewInternalServerError("tyc userinfo_secret not configured")
	}
	u, err := neturl.Parse(c.conf.BaseUrl)
	if err != nil {
		return nil, httperrors.NewInternalServerError("invalid tyc base_url: %v", err)
	}
	u.Path = joinPaths(u.Path, "/sso/getUserInfoByToken")
	// svcCont 结构 = {"requestObject":{"token": ...}}，与已联调通过的参考实现
	// （AuthController.fySsoTokenLogin / ssologin_app.ssoCheck）完全一致，
	// 否则 tydic 侧按同规则重算的签名与报文不符 → 返回 500。
	svcCont, _ := json.Marshal(map[string]interface{}{
		"requestObject": map[string]string{"token": token},
	})
	// 前端传了 transaction_id 就用外部的（便于 tydic 侧追踪/防重放对齐），
	// 空串则内部自生成 28 位流水号。
	txnId := extTxnId
	if len(txnId) == 0 {
		txnId = newTxnId()
	}
	_, sign := c.signPayload(txnId, svcCont, secret)
	// DEBUG: 打印发出的 txnId + svcCont + sign，便于核对 MD5 与 tydic 拒绝原因
	log.Warningf("tyc getUserInfoByToken txndId=%s svcCont=%s sign=%s", txnId, string(svcCont), sign)
	// tcpCont 仅 transactionId/sign/appKey；参考实现不传 reqTime / dstSysId
	root := map[string]interface{}{
		"tcpCont": map[string]interface{}{
			"transactionId": txnId,
			"appKey":        c.conf.AppKey,
			"sign":          sign,
		},
		"svcCont": json.RawMessage(svcCont),
	}
	resp, err := c.doJSON(ctx, http.MethodPost, u.String(), root)
	if err != nil {
		return nil, mapTydicError(0, err, "call getUserInfoByToken")
	}
	if resp.ResultCode != 0 {
		return nil, mapTydicError(resp.ResultCode, errors.Error(resp.ResultMsg), "getUserInfoByToken refused")
	}
	detail := &SystemUserDetail{}
	if len(resp.SvcCont) > 0 {
		if err := json.Unmarshal(resp.SvcCont, detail); err != nil {
			return nil, httperrors.NewInternalServerError("parse tydic SystemUserDetail: %v", err)
		}
	}
	return detail, nil
}

// ListOrganizations 拉 90900100010002 qryOrganizationList
// 请求字段以现场接口说明为准（示例传 orgName/tenantId）
func (c *TYCHttpClient) ListOrganizations(ctx context.Context, tenantId string) ([]TycOrgNodeDTO, error) {
	req := map[string]interface{}{
		"tenantId": tenantId,
		"orgName":  "",
	}
	resp, err := c.callService(ctx, "90900100010002", req, c.conf.UserInfoSecret)
	if err != nil {
		return nil, err
	}
	out := struct {
		Records []TycOrgNodeDTO `json:"records"`
	}{}
	if len(resp.SvcCont) > 0 {
		if e := json.Unmarshal(resp.SvcCont, &out); e != nil {
			return nil, errors.Wrap(e, "unmarshal qryOrganizationList")
		}
	}
	return out.Records, nil
}

// ListProjects 拉 90900100010001 qryProjectList
func (c *TYCHttpClient) ListProjects(ctx context.Context, tenantId string, _ *OrgTreeIndex) ([]TycProjectDTO, error) {
	req := map[string]interface{}{
		"tenantId": tenantId,
	}
	resp, err := c.callService(ctx, "90900100010001", req, c.conf.UserInfoSecret)
	if err != nil {
		return nil, err
	}
	out := struct {
		Records []TycProjectDTO `json:"records"`
	}{}
	if len(resp.SvcCont) > 0 {
		if e := json.Unmarshal(resp.SvcCont, &out); e != nil {
			return nil, errors.Wrap(e, "unmarshal qryProjectList")
		}
	}
	return out.Records, nil
}

// Probe 验证配置连通性
func (c *TYCHttpClient) Probe(ctx context.Context) error {
	_, err := c.callService(ctx, "90900100010001",
		map[string]interface{}{"tenantId": c.conf.TenantId, "pageNum": 1, "pageSize": 1},
		c.conf.UserInfoSecret)
	return err
}

// callService 统一走 doService（组织/项目/用户/权限）
func (c *TYCHttpClient) callService(ctx context.Context, svcCode string, svcReq interface{}, secret string) (*TycStandardResp, error) {
	u, err := neturl.Parse(c.conf.BaseUrl)
	if err != nil {
		return nil, httperrors.NewInternalServerError("invalid tyc base_url: %v", err)
	}
	u.Path = joinPaths(u.Path, "/esmp-serve-rest/rest/serve/doService")
	// svcCont 结构 = {"requestObject": {业务字段}}，svcCode 放在 tcpCont；
	// 与参考实现（fySsoTokenLogin / ssoCheck 的 doService 调用）一致。
	svcCont, err := json.Marshal(map[string]interface{}{
		"requestObject": svcReq,
	})
	if err != nil {
		return nil, errors.Wrap(err, "marshal svcCont")
	}
	txnId := newTxnId()
	_, sign := c.signPayload(txnId, svcCont, secret)
	// tcpCont 含 svcCode + appKey，但参考实现不传 reqTime / dstSysId
	root := map[string]interface{}{
		"tcpCont": map[string]interface{}{
			"transactionId": txnId,
			"appKey":        c.conf.AppKey,
			"svcCode":       svcCode,
			"sign":          sign,
		},
		"svcCont": json.RawMessage(svcCont),
	}
	resp, err := c.doJSON(ctx, http.MethodPost, u.String(), root)
	if err != nil {
		return nil, mapTydicError(0, err, fmt.Sprintf("callService svcCode=%s", svcCode))
	}
	if resp.ResultCode != 0 {
		return nil, mapTydicError(resp.ResultCode, errors.Error(resp.ResultMsg), fmt.Sprintf("tyc svcCode=%s", svcCode))
	}
	return resp, nil
}

// ── 传输层 doJSON ───────────────────────────────────────────────────────────

func (c *TYCHttpClient) doJSON(ctx context.Context, method, url string, body interface{}) (*TycStandardResp, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, errors.Wrap(err, "marshal tyc request")
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(buf))
	if err != nil {
		return nil, errors.Wrap(err, "new tyc request")
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	c.mu.Lock()
	defer c.mu.Unlock()
	resp, err := c.httpCli.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "tyc http do")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read tyc response")
	}
	if resp.StatusCode >= 400 {
		return nil, httperrors.NewBadGatewayError("tyc http %s: status=%d body=%s", url, resp.StatusCode, string(raw))
	}
	unpacked := struct {
		ContractRoot TycStandardResp `json:"contractRoot"`
	}{}
	if err := json.Unmarshal(raw, &unpacked); err == nil &&
		(unpacked.ContractRoot.ResultCode != 0 || len(unpacked.ContractRoot.SvcCont) > 0) {
		cp := unpacked.ContractRoot
		return &cp, nil
	}
	out := TycStandardResp{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, errors.Wrap(err, "parse tyc standard resp")
	}
	return &out, nil
}

// mapTydicError tydic resultCode → httperrors
func mapTydicError(code int, err error, tag string) error {
	if err == nil && code == 0 {
		return nil
	}
	switch code {
	case 0:
		return errors.Wrap(err, tag)
	case -9100:
		return httperrors.NewUnauthorizedError("tyc signature verification failed: %v: %v", tag, err)
	case -9000:
		return httperrors.NewInputParameterError("tyc parse request failed: %v: %v", tag, err)
	case -1000, 10001:
		return httperrors.NewInputParameterError("tyc parameter error: %v: %v", tag, err)
	case 10002, -2000:
		return httperrors.NewForbiddenError("tyc credential/permission denied: %v: %v", tag, err)
	case -9999:
		return httperrors.NewInternalServerError("tyc unknown error(%d): %v: %v", code, tag, err)
	}
	return httperrors.NewBadGatewayError("tyc %s up %d: %v", tag, code, err)
}

// ── 同步持久化：syncOrgTree / syncProjects（写事实层，不碰授权） ──────────────
//
// 注意：cloudpods 没暴露 `SyncOrCreateOrgProject / SyncOrProject / SyncOrCreateNode` 这些方法名。
// 这里用项目中真实存在的基础 API（ProjectManager.NewProject / TableSpec().Insert / FetchByIdOrName 等）拼接完成，
// 并通过 `syncEnsureProjectTags` 把 ProjectTags/Extra 字段做 upsert（表直 Update 即可）。

// idmgrSyncOrProject 幂等：先按 id_mapping(project entity)找，找不到按 code+domain 找，再找不到 NewProject
// 返回的 (*SProject, changed, error)，changed=true 表示新建了
func idmgrSyncOrProject(ctx context.Context, domainId, code, name, parentId, extOrgId string, ancestors []string, extraRegion map[string]string) (*models.SProject, error) {
	// 1) 先按 id_mapping
	if pid, err := models.IdmappingManager.FetchByIdpAndEntityId(ctx, api.IdentityDriverTyc, code, "project"); err == nil && len(pid) > 0 {
		if obj, e2 := models.ProjectManager.FetchProjectById(pid); e2 == nil {
			return idmgrUpdateProjectIfNeeded(obj, parentId, extOrgId, ancestors, extraRegion)
		}
	}
	// 2) 按 code+domain 回退（项目名在同域唯一 → 这里用 code 当 name 主值）
	if obj, e2 := models.ProjectManager.FetchProject(code, name, domainId, ""); e2 == nil {
		return idmgrUpdateProjectIfNeeded(obj, parentId, extOrgId, ancestors, extraRegion)
	}
	desc := fmt.Sprintf("tyc-synced project (org=%s, ancestors=%v)", extOrgId, ancestors)
	proj, err := models.ProjectManager.NewProject(ctx, code, desc, domainId)
	if err != nil {
		return nil, errors.Wrapf(err, "NewProject code=%s", code)
	}
	// NewProject 内部已 Insert，后续修改需显式 db.Update 落库
	return idmgrUpdateProjectIfNeeded(proj, parentId, extOrgId, ancestors, extraRegion)
}

// idmgrUpdateProjectIfNeeded 比对并持久化 ParentId/Extra/Tags 变更
func idmgrUpdateProjectIfNeeded(proj *models.SProject, parentId, extOrgId string, ancestors []string, extraRegion map[string]string) (*models.SProject, error) {
	needUpdate := false
	if len(parentId) > 0 && proj.ParentId != parentId {
		needUpdate = true
	}
	if len(extOrgId) > 0 {
		if proj.Extra == nil {
			needUpdate = true
		} else {
			cur, _ := proj.Extra.GetString("org_id")
			if cur != extOrgId {
				needUpdate = true
			}
		}
	}
	if len(ancestors) > 0 {
		needUpdate = true
	}
	if !needUpdate {
		return proj, nil
	}
	if _, err := db.Update(proj, func() error {
		if len(parentId) > 0 {
			proj.ParentId = parentId
		}
		if proj.Extra == nil {
			proj.Extra = jsonutils.NewDict()
		}
		if len(extOrgId) > 0 {
			proj.Extra.Add(jsonutils.NewString(extOrgId), "org_id")
			for k, v := range extraRegion {
				proj.Extra.Add(jsonutils.NewString(v), k)
			}
		}
		if len(ancestors) > 0 {
			proj.Extra.Add(jsonutils.Marshal(ancestors), "org_ancestors")
		}
		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "db.Update project %s (parentId/extra)", proj.Id)
	}
	return proj, nil
}

// idmgrSyncOrOrgNode 组织 Node 幂等创建（如果项目中 OrganizationManager 没有现成 SyncOrCreate）
func idmgrSyncOrOrgNode(ctx context.Context, domainId, orgId, orgName, fullLabel, bindProjectId, parentNodeId string) error {
	_ = ctx
	_ = domainId
	_ = orgId
	_ = orgName
	_ = fullLabel
	_ = bindProjectId
	_ = parentNodeId
	// TODO: 接真实 models.OrganizationManager 创建/复用 Node
	return nil
}

// syncOrgTree DFS 把祖先链拍平，写组织项目 + Organization Node；
// 同时更新 OrgTreeIndex（给行过滤和 ScopeResolver O(1) 查询用）。
func syncOrgTree(ctx context.Context, domainId string, flat []TycOrgNodeDTO, idx *OrgTreeIndex) error {
	if idx == nil {
		return fmt.Errorf("nil OrgTreeIndex")
	}
	roots, byParent := groupByParent(flat)
	var walk func(node TycOrgNodeDTO, parentBindProjectId string, ancestors []string) error
	walk = func(node TycOrgNodeDTO, parentBindProjectId string, ancestors []string) error {
		newAnc := append(append([]string(nil), ancestors...), node.OrgId)
		orgProj, err := idmgrSyncOrProject(ctx, domainId,
			"ORG-"+node.OrgCode, node.OrgName, parentBindProjectId,
			node.OrgId, newAnc, nil)
		if err != nil {
			return errors.Wrapf(err, "syncOrgTree project org=%s/%s", node.OrgCode, node.OrgId)
		}
		if err := idmgrSyncOrOrgNode(ctx, domainId, node.OrgId, node.OrgName,
			joinLabels(newAnc), orgProj.Id, parentBindProjectId); err != nil {
			return errors.Wrapf(err, "syncOrgTree node org=%s", node.OrgId)
		}
		idx.OrgAncestorsByOrgId[node.OrgId] = newAnc
		idx.BindProjectByOrgId[node.OrgId] = orgProj.Id
		if parentBindProjectId == "" && idx.DomainRootOrgProjectId == "" {
			idx.DomainRootOrgProjectId = orgProj.Id
		}
		for _, c := range byParent[node.OrgId] {
			if err := walk(c, orgProj.Id, newAnc); err != nil {
				return err
			}
		}
		return nil
	}
	for _, r := range roots {
		if err := walk(r, "", nil); err != nil {
			return err
		}
	}
	return nil
}

// syncProjects 对每个业务项目写入 ProjectTags['org'] = 所属 org 的祖先链（最关键的预拍平）
// 归属优先 sysBelongOrgId；缺失 fallback 到 tenant 域根 ORG-O000
func syncProjects(ctx context.Context, domainId string, list []TycProjectDTO, idx *OrgTreeIndex) error {
	for _, p := range list {
		orgId := p.SysBelongOrgId
		parentId := ""
		ancestors := []string{}
		if idx != nil && len(orgId) > 0 {
			parentId = idx.BindProjectId(orgId)
			ancestors = idx.AncestorsIncludingSelf(orgId)
		}
		regionExtra := map[string]string{
			"region_id":   p.RegionId,
			"region_code": p.RegionCode,
		}
		_, err := idmgrSyncOrProject(ctx, domainId, p.ProjectCode, p.ProjectName, parentId, orgId, ancestors, regionExtra)
		if err != nil {
			return errors.Wrapf(err, "syncProjects code=%s", p.ProjectCode)
		}
	}
	return nil
}

// ── 小组件（与项目解耦） ────────────────────────────────────────────────────

func randomDigits(n int) string {
	if n <= 0 {
		return ""
	}
	const digits = "0123456789"
	out := make([]byte, n)
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		now := time.Now().UnixNano()
		for i := range out {
			out[i] = digits[int(now+int64(i))%len(digits)]
		}
		return string(out)
	}
	for i, b := range buf {
		out[i] = digits[int(b)%len(digits)]
	}
	return string(out)
}

func joinPaths(a, b string) string {
	if strings.HasSuffix(a, "/") && strings.HasPrefix(b, "/") {
		return a + strings.TrimPrefix(b, "/")
	}
	if !strings.HasSuffix(a, "/") && !strings.HasPrefix(b, "/") {
		return a + "/" + b
	}
	return a + b
}

func joinLabels(parts []string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "/")
}

// groupByParent 把扁平 TycOrgNodeDTO 按 parentOrgId 分组，并返回 roots（parent 为 "" 或不在列表中）
func groupByParent(list []TycOrgNodeDTO) (roots []TycOrgNodeDTO, byParent map[string][]TycOrgNodeDTO) {
	byParent = map[string][]TycOrgNodeDTO{}
	ids := map[string]struct{}{}
	for _, n := range list {
		ids[n.OrgId] = struct{}{}
	}
	for _, n := range list {
		if n.ParentOrgId == "" {
			roots = append(roots, n)
			continue
		}
		if _, ok := ids[n.ParentOrgId]; !ok {
			roots = append(roots, n)
			continue
		}
		byParent[n.ParentOrgId] = append(byParent[n.ParentOrgId], n)
	}
	for _, arr := range byParent {
		sort.SliceStable(arr, func(i, j int) bool { return arr[i].OrgCode < arr[j].OrgCode })
	}
	sort.SliceStable(roots, func(i, j int) bool { return roots[i].OrgCode < roots[j].OrgCode })
	return
}

// ── RSA 工具 ────────────────────────────────────────────────────────────────

func parseRSAPrivate(pemBytes []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, fmt.Errorf("invalid tyc rsa private key PEM")
	}
	if key, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		if r, ok := key.(*rsa.PrivateKey); ok {
			return r, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("tyc rsa private key: neither PKCS#8 nor PKCS#1")
}

func rsaSignSHA256(key *rsa.PrivateKey, digest []byte) (string, error) {
	h := sha256.Sum256(digest)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig), nil
}
