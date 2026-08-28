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

package models

import (
	"context"
	"regexp"
	"strings"

	"yunion.io/x/jsonutils"
	"yunion.io/x/log"
	"yunion.io/x/pkg/errors"
	"yunion.io/x/sqlchemy"

	api "yunion.io/x/onecloud/pkg/apis/compute"
	"yunion.io/x/onecloud/pkg/cloudcommon/db"
	"yunion.io/x/onecloud/pkg/cloudcommon/validators"
	"yunion.io/x/onecloud/pkg/httperrors"
	"yunion.io/x/onecloud/pkg/mcclient"
	"yunion.io/x/onecloud/pkg/util/stringutils2"
)

// [AGC:START] tool=Cc date=2026-08-26 author=sniper / 挂载点合法性校验：绝对路径且不含空白字符（前导/后置空格导致 mount exit 32 的教训） /
var mountPointReg = regexp.MustCompile(`^/[^\s]*$`)

// 挂载选项值安全字符（防 `;` 等命令注入字符进入 mount 命令/fstab）
var mountOptionValueReg = regexp.MustCompile(`^[A-Za-z0-9._:/-]*$`)

// 挂载选项白名单（仅允许常见 NFS 挂载选项，防任意内容注入 fstab）
var mountOptionWhitelist = map[string]bool{
	"nfsvers": true,
	"rsize":   true,
	"wsize":   true,
	"hard":    true,
	"soft":    true,
	"timeo":   true,
	"retrans": true,
	"rw":      true,
	"ro":      true,
	"nolock":  true,
	"noatime": true,
	"actimeo": true,
}

// 默认挂载选项：锁定 NFSv4.2 单端口 2049 绕开 v3 动态端口防火墙坑；hard 挂载适配训练场景（服务器抖动持续重试）
const DEFAULT_MOUNT_OPTIONS = "nfsvers=4.2,hard,timeo=600,rsize=1048576,wsize=1048576"

func validateMountOptions(options string) error {
	if options == "" {
		return nil
	}
	parts := strings.Split(options, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if !mountOptionWhitelist[kv[0]] {
			return httperrors.NewInputParameterError("unsupported mount option: %s", kv[0])
		}
		if len(kv) == 2 && !mountOptionValueReg.MatchString(kv[1]) {
			return httperrors.NewInputParameterError("invalid mount option value: %s", part)
		}
	}
	return nil
}

// [AGC:END]

// +onecloud:swagger-gen-ignore
// [AGC:START] tool=Cc date=2026-08-26 author=sniper / 挂载关系 manager 与注册 /
type SBaremetalStorageMountManager struct {
	SHostJointsManager
	SStorageResourceBaseManager
}

var BaremetalStorageMountManager *SBaremetalStorageMountManager

func init() {
	db.InitManager(func() {
		BaremetalStorageMountManager = &SBaremetalStorageMountManager{
			SHostJointsManager: NewHostJointsManager(
				"host_id",
				SBaremetalStorageMount{},
				"baremetal_storage_mounts_tbl",
				"baremetalstoragemount",
				"baremetalstoragemounts",
				StorageManager,
			),
		}
		BaremetalStorageMountManager.SetVirtualObject(BaremetalStorageMountManager)
		BaremetalStorageMountManager.TableSpec().AddIndex(false, "host_id", "storage_id")
	})
}

// [AGC:END]

// [AGC:START] tool=Cc date=2026-08-26 author=sniper / 挂载关系模型（本体 mountStorage 关系实体化；+onecloud:model-api-gen 标记须紧贴 type 行） /
// +onecloud:model-api-gen
type SBaremetalStorageMount struct {
	SHostJointsBase

	// 裸金属物理机Id
	HostId string `width:"36" charset:"ascii" nullable:"false" list:"domain" create:"required" json:"host_id"`
	// 外接存储Id
	StorageId string `width:"36" charset:"ascii" nullable:"false" list:"domain" create:"required" json:"storage_id" index:"true"`

	// 挂载点（客户 OS 内绝对路径）
	MountPoint string `width:"256" charset:"ascii" nullable:"false" list:"domain" create:"required" json:"mount_point"`
	// 挂载选项（NFS 挂载选项，白名单校验）
	MountOptions string `width:"256" charset:"ascii" nullable:"false" list:"domain" create:"required" json:"mount_options"`
	// 挂载状态：init/mounting/mounted/failed
	MountStatus string `width:"16" charset:"ascii" nullable:"false" default:"init" list:"domain" create:"optional" json:"mount_status"`
	// 最近一次失败信息
	LastError string `width:"512" charset:"utf8" nullable:"true" list:"domain" json:"last_error"`
}

// [AGC:END]

func (manager *SBaremetalStorageMountManager) GetMasterFieldName() string {
	return "host_id"
}

func (manager *SBaremetalStorageMountManager) GetSlaveFieldName() string {
	return "storage_id"
}

func (manager *SBaremetalStorageMountManager) FetchCustomizeColumns(
	ctx context.Context,
	userCred mcclient.TokenCredential,
	query jsonutils.JSONObject,
	objs []interface{},
	fields stringutils2.SSortedStrings,
	isList bool,
) []api.BaremetalStorageMountDetails {
	rows := make([]api.BaremetalStorageMountDetails, len(objs))
	hostRows := manager.SHostJointsManager.FetchCustomizeColumns(ctx, userCred, query, objs, fields, isList)
	storageIds := make([]string, len(rows))

	for i := range rows {
		rows[i] = api.BaremetalStorageMountDetails{
			HostJointResourceDetails: hostRows[i],
		}
		storageIds[i] = objs[i].(*SBaremetalStorageMount).StorageId
	}

	storages := make(map[string]SStorage)
	err := db.FetchStandaloneObjectsByIds(StorageManager, storageIds, &storages)
	if err != nil {
		log.Errorf("db.FetchStandaloneObjectsByIds fail %s", err)
		return rows
	}

	for i := range rows {
		if storage, ok := storages[storageIds[i]]; ok {
			rows[i].Storage = storage.Name
			rows[i].StorageType = storage.StorageType
		}
	}

	return rows
}

func (self *SBaremetalStorageMount) GetHost() *SHost {
	host, _ := HostManager.FetchById(self.HostId)
	if host != nil {
		return host.(*SHost)
	}
	return nil
}

func (self *SBaremetalStorageMount) GetStorage() *SStorage {
	storage, err := StorageManager.FetchById(self.StorageId)
	if err != nil {
		log.Errorf("BaremetalStorageMount fetch storage %q error: %v", self.StorageId, err)
	}
	if storage != nil {
		return storage.(*SStorage)
	}
	return nil
}

// [AGC:START] tool=Cc date=2026-08-26 author=sniper / 校验：host 须为裸金属、storage 须为 NFS（本期协议）、挂载点格式、选项白名单、重复绑定拒绝 /
func (manager *SBaremetalStorageMountManager) ValidateCreateData(ctx context.Context, userCred mcclient.TokenCredential, ownerId mcclient.IIdentityProvider, query jsonutils.JSONObject, input api.BaremetalStorageMountCreateInput) (api.BaremetalStorageMountCreateInput, error) {
	hostObj, err := validators.ValidateModel(ctx, userCred, HostManager, &input.HostId)
	if err != nil {
		return input, err
	}
	host := hostObj.(*SHost)
	if !host.IsBaremetal {
		return input, httperrors.NewInputParameterError("host %s is not a baremetal host", host.GetName())
	}
	storageObj, err := validators.ValidateModel(ctx, userCred, StorageManager, &input.StorageId)
	if err != nil {
		return input, err
	}
	storage := storageObj.(*SStorage)
	if storage.StorageType != api.STORAGE_NFS {
		return input, httperrors.NewInputParameterError("storage %s type %s is not supported, only nfs is supported", storage.GetName(), storage.StorageType)
	}
	if !mountPointReg.MatchString(input.MountPoint) {
		return input, httperrors.NewInputParameterError("mount_point must be an absolute path without whitespace")
	}
	if input.MountOptions == "" {
		input.MountOptions = DEFAULT_MOUNT_OPTIONS
	}
	if err := validateMountOptions(input.MountOptions); err != nil {
		return input, err
	}
	q := manager.Query().Equals("host_id", input.HostId).Equals("storage_id", input.StorageId)
	cnt, err := q.CountWithError()
	if err != nil {
		return input, errors.Wrap(err, "check duplicate mount relation")
	}
	if cnt > 0 {
		return input, httperrors.NewConflictError("mount relation between host %s and storage %s already exists", host.GetName(), storage.GetName())
	}
	input.JoinResourceBaseCreateInput, err = manager.SJointResourceBaseManager.ValidateCreateData(ctx, userCred, ownerId, query, input.JoinResourceBaseCreateInput)
	if err != nil {
		return input, err
	}
	return input, nil
}

// [AGC:END]

func (manager *SBaremetalStorageMountManager) ListItemFilter(
	ctx context.Context,
	q *sqlchemy.SQuery,
	userCred mcclient.TokenCredential,
	query api.BaremetalStorageMountListInput,
) (*sqlchemy.SQuery, error) {
	var err error

	q, err = manager.SHostJointsManager.ListItemFilter(ctx, q, userCred, query.HostJointsListInput)
	if err != nil {
		return nil, errors.Wrap(err, "SHostResourceBaseManager.ListItemFilter")
	}
	q, err = manager.SStorageResourceBaseManager.ListItemFilter(ctx, q, userCred, query.StorageFilterListInput)
	if err != nil {
		return nil, errors.Wrap(err, "SStorageResourceBaseManager.ListItemFilter")
	}
	if len(query.MountStatus) > 0 {
		q = q.Equals("mount_status", query.MountStatus)
	}

	return q, nil
}

func (manager *SBaremetalStorageMountManager) OrderByExtraFields(
	ctx context.Context,
	q *sqlchemy.SQuery,
	userCred mcclient.TokenCredential,
	query api.BaremetalStorageMountListInput,
) (*sqlchemy.SQuery, error) {
	var err error

	q, err = manager.SHostJointsManager.OrderByExtraFields(ctx, q, userCred, query.HostJointsListInput)
	if err != nil {
		return nil, errors.Wrap(err, "SHostResourceBaseManager.OrderByExtraFields")
	}
	q, err = manager.SStorageResourceBaseManager.OrderByExtraFields(ctx, q, userCred, query.StorageFilterListInput)
	if err != nil {
		return nil, errors.Wrap(err, "SStorageResourceBaseManager.OrderByExtraFields")
	}

	return q, nil
}

func (manager *SBaremetalStorageMountManager) ListItemExportKeys(ctx context.Context,
	q *sqlchemy.SQuery,
	userCred mcclient.TokenCredential,
	keys stringutils2.SSortedStrings,
) (*sqlchemy.SQuery, error) {
	var err error

	q, err = manager.SHostJointsManager.ListItemExportKeys(ctx, q, userCred, keys)
	if err != nil {
		return nil, errors.Wrap(err, "SHostJointsManager.ListItemExportKeys")
	}
	if keys.ContainsAny(manager.SStorageResourceBaseManager.GetExportKeys()...) {
		q, err = manager.SStorageResourceBaseManager.ListItemExportKeys(ctx, q, userCred, keys)
		if err != nil {
			return nil, errors.Wrap(err, "SStorageResourceBaseManager.ListItemExportKeys")
		}
	}

	return q, nil
}

// [AGC:START] tool=Cc date=2026-08-26 author=sniper / 按宿主机查询全部挂载关系 /
func (manager *SBaremetalStorageMountManager) GetMountsByHostId(hostId string) ([]SBaremetalStorageMount, error) {
	mounts := make([]SBaremetalStorageMount, 0)
	q := manager.Query().Equals("host_id", hostId)
	err := db.FetchModelObjects(manager, q, &mounts)
	if err != nil {
		return nil, errors.Wrap(err, "FetchModelObjects")
	}
	return mounts, nil
}

// [AGC:END]
