package models

import (
	"context"
	"encoding/json"

	"yunion.io/x/sqlchemy"

	"yunion.io/x/onecloud/pkg/cloudcommon/db"
)

func init() {
	db.RegisterOrgSubtreeProjectResolver(listProjectIdsByOrgIds)
	db.RegisterTycScopeLoader(loadTycScopeDTO)
}

// loadTycScopeDTO 从 SUser.Extra['tyc_scope'] 加载 TycScopeFilterDTO
func loadTycScopeDTO(ctx context.Context, userId string) *db.TycScopeFilterDTO {
	usr, err := UserManager.FetchById(userId)
	if err != nil {
		return nil
	}
	suser, ok := usr.(*SUser)
	if !ok || suser == nil || suser.Extra == nil {
		return nil
	}
	scopeJSON, err := suser.Extra.GetString("tyc_scope")
	if err != nil || len(scopeJSON) == 0 {
		return nil
	}
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
	if err := json.Unmarshal([]byte(scopeJSON), &ts); err != nil || len(ts.DataScope.Level) == 0 {
		return nil
	}
	return &db.TycScopeFilterDTO{
		Level:      ts.DataScope.Level,
		DomainId:   ts.TenantId,
		OrgId:      ts.DataScope.OrgId,
		OrgIds:     ts.DataScope.OrgIds,
		ProjectIds: ts.DataScope.ProjectIds,
	}
}

// listProjectIdsByOrgIds 查找给定域下 Extra['org_ancestors'] 包含任一 orgId 的所有项目 ID。
// 这对应"组织子树下的所有业务项目"：如果项目的祖先链中包含目标 orgId，则该项目在该 org 子树下。
// 实现：查 project 表的 extra TEXT 列，LIKE 匹配 orgId 字符串出现。
func listProjectIdsByOrgIds(ctx context.Context, domainId string, orgIds []string) ([]string, error) {
	if len(orgIds) == 0 {
		return nil, nil
	}
	q := ProjectManager.Query("id")
	q = q.Equals("domain_id", domainId)
	q = q.IsFalse("is_domain")

	// extra 列存 JSON: {"org_id":"O011","org_ancestors":["O000","O010","O011"],...}
	// 匹配逻辑：extra LIKE '%"orgId1"%' OR extra LIKE '%"orgId2"%'
	// 这会匹配 org_id 或 org_ancestors 中含该 orgId 的项目（两者都符合子树语义）
	conditions := make([]sqlchemy.ICondition, 0, len(orgIds))
	for _, oid := range orgIds {
		conditions = append(conditions, sqlchemy.Contains(q.Field("extra"), oid))
	}
	if len(conditions) == 1 {
		q = q.Filter(conditions[0])
	} else {
		q = q.Filter(sqlchemy.OR(conditions...))
	}

	rows, err := q.Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, nil
}
