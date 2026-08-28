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

package compute

import (
	"yunion.io/x/onecloud/pkg/apis"
)

// [AGC:START] tool=Cc date=2026-08-26 author=sniper / 裸金属外接存储挂载状态（对应本体 mountStorage 关系 mountStatus） /
const (
	BAREMETAL_STORAGE_MOUNT_STATUS_INIT     = "init"
	BAREMETAL_STORAGE_MOUNT_STATUS_MOUNTING = "mounting"
	BAREMETAL_STORAGE_MOUNT_STATUS_MOUNTED  = "mounted"
	BAREMETAL_STORAGE_MOUNT_STATUS_FAILED   = "failed"
)

// [AGC:END]

// [AGC:START] tool=Cc date=2026-08-26 author=sniper / 挂载关系详情（联合资源详情 + 存储信息） /
type BaremetalStorageMountDetails struct {
	HostJointResourceDetails
	SBaremetalStorageMount

	// 存储名称
	Storage string `json:"storage"`
	// 存储类型
	StorageType string `json:"storage_type"`
}

// [AGC:END]

// [AGC:START] tool=Cc date=2026-08-26 author=sniper / 挂载关系列表查询输入 /
type BaremetalStorageMountListInput struct {
	HostJointsListInput

	StorageFilterListInput

	MountStatus string `json:"mount_status"`
}

// [AGC:END]

// [AGC:START] tool=Cc date=2026-08-26 author=sniper / 挂载关系创建输入（绑定） /
type BaremetalStorageMountCreateInput struct {
	apis.JoinResourceBaseCreateInput

	HostId       string `json:"host_id"`
	StorageId    string `json:"storage_id"`
	MountPoint   string `json:"mount_point"`
	MountOptions string `json:"mount_options"`
}

// [AGC:END]
