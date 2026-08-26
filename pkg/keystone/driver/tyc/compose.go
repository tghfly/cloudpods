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
	"strings"
)

// MenuResourceMapping menuCode → service/resource 映射（配置表驱动）
type MenuResourceMapping struct {
	Entries map[string]string // menuCode → "service/resource"
}

// DefaultMenuResourceMapping 默认映射表（联调时按现场 705 接口补充）
var DefaultMenuResourceMapping = &MenuResourceMapping{
	Entries: map[string]string{
		"vm_manage":       "compute/servers",
		"disk_manage":     "compute/disks",
		"network_manage":  "compute/networks",
		"eip_manage":      "compute/eips",
		"secgroup_manage": "compute/secgroups",
		"lb_manage":       "compute/loadbalancers",
		"image_manage":    "image/images",
		"snapshot_manage": "compute/snapshots",
		"vpc_manage":      "compute/vpcs",
		"bucket_manage":   "compute/buckets",
		"rds_manage":      "compute/dbinstances",
		"redis_manage":    "compute/elasticcaches",
		"user_manage":     "identity/users",
		"project_manage":  "identity/projects",
		"role_manage":     "identity/roles",
		"policy_manage":   "identity/policies",
		"k8s_cluster":     "k8s/kubeclusters",
		"k8s_deploy":      "k8s/deployments",
		"k8s_pod":         "k8s/pods",
		"k8s_service":     "k8s/k8s_services",
		"monitor_alert":   "monitor/meter_alerts",
	},
}

// Resolve 根据 menuCode 返回 "service/resource"，未找到返回空
func (m *MenuResourceMapping) Resolve(menuCode string) string {
	if m == nil || m.Entries == nil {
		return ""
	}
	return m.Entries[strings.ToLower(strings.TrimSpace(menuCode))]
}

// TycPrivsMenuItem 705 接口返回的单条功能/菜单权限
type TycPrivsMenuItem struct {
	MenuCode      string   `json:"menuCode"`
	OperationType []string `json:"operationType"`
}

// TycPrivsResponse 705 接口权限响应（简化结构，按现场字段调整）
type TycPrivsResponse struct {
	FuncMenus  []TycPrivsMenuItem `json:"funcMenusAndCompsList"`
	Operations []string           `json:"operations,omitempty"`
}

// ComposeActionOverrides 把 705 返回的逐条权限合成为 ActionLevel + ActionOverrides。
// 在登录 PostAuthenticate 阶段调用，结果写入 TycScope。
func ComposeActionOverrides(privs *TycPrivsResponse, mapping *MenuResourceMapping) (ActionLevel, []ActionOverride) {
	if privs == nil || len(privs.FuncMenus) == 0 {
		return ActionLevelReadonly, nil
	}
	if mapping == nil {
		mapping = DefaultMenuResourceMapping
	}

	perResource := map[string][]string{}
	for _, item := range privs.FuncMenus {
		sr := mapping.Resolve(item.MenuCode)
		if sr == "" {
			continue
		}
		actions := MapOperationsToActions(item.OperationType)
		perResource[sr] = mergeUnique(perResource[sr], actions)
	}

	if len(perResource) == 0 {
		return ActionLevelReadonly, nil
	}

	baseline := inferBaseline(perResource)
	baselineActions := ActionsForLevel(baseline)

	var overrides []ActionOverride
	for sr, actions := range perResource {
		extra := difference(actions, baselineActions)
		missing := difference(baselineActions, actions)
		if len(extra) == 0 && len(missing) == 0 {
			continue
		}
		parts := strings.SplitN(sr, "/", 2)
		if len(parts) != 2 {
			continue
		}
		ov := ActionOverride{Service: parts[0], Resource: parts[1]}
		if len(extra) > 0 {
			ov.Allow = extra
		}
		if len(missing) > 0 {
			ov.Deny = missing
		}
		overrides = append(overrides, ov)
	}
	return baseline, overrides
}

// MapOperationsToActions 将 tydic operationType → cloudpods actions
func MapOperationsToActions(ops []string) []string {
	var out []string
	for _, op := range ops {
		switch strings.ToLower(strings.TrimSpace(op)) {
		case "query", "查询", "view", "查看", "list", "get":
			out = append(out, "list", "get")
		case "add", "新建", "create":
			out = append(out, "create")
		case "edit", "编辑", "modify", "修改", "update":
			out = append(out, "update", "perform")
		case "del", "删除", "delete", "remove":
			out = append(out, "delete")
		case "*", "all", "全部":
			out = append(out, "list", "get", "create", "update", "delete", "perform")
		}
	}
	return unique(out)
}

// inferBaseline 统计全部资源的动作并集，推导"最小公约"ActionLevel
func inferBaseline(perResource map[string][]string) ActionLevel {
	if len(perResource) == 0 {
		return ActionLevelReadonly
	}
	allHaveCreate := true
	allHaveDelete := true
	allHaveUpdate := true
	for _, actions := range perResource {
		actionSet := toSet(actions)
		if _, ok := actionSet["create"]; !ok {
			allHaveCreate = false
		}
		if _, ok := actionSet["delete"]; !ok {
			allHaveDelete = false
		}
		if _, ok := actionSet["update"]; !ok {
			allHaveUpdate = false
		}
	}
	if allHaveCreate && allHaveDelete {
		return ActionLevelFull
	}
	if allHaveUpdate {
		return ActionLevelEditor
	}
	return ActionLevelReadonly
}

// ── 工具函数 ─────────────────────────────────────────────────────────────

func toSet(xs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		m[x] = struct{}{}
	}
	return m
}

func unique(xs []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}

func mergeUnique(a, b []string) []string {
	seen := toSet(a)
	out := append([]string(nil), a...)
	for _, x := range b {
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}

func difference(a, b []string) []string {
	bSet := toSet(b)
	var out []string
	for _, x := range a {
		if _, ok := bSet[x]; !ok {
			out = append(out, x)
		}
	}
	return out
}
