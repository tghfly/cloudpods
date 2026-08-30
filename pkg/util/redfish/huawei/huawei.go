// [AGC:START] tool=Cc date=2026-08-28 author=tangguanghui@tydic.com
package huawei

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"yunion.io/x/jsonutils"
	"yunion.io/x/log"
	"yunion.io/x/pkg/errors"

	"yunion.io/x/onecloud/pkg/util/redfish"
	"yunion.io/x/onecloud/pkg/util/redfish/generic"
)

type SHuaweiRedfishApiFactory struct {
}

func (f *SHuaweiRedfishApiFactory) Name() string {
	return "Huawei"
}

func (f *SHuaweiRedfishApiFactory) NewApi(endpoint, username, password string, debug bool) redfish.IRedfishDriver {
	return NewHuaweiRedfishApi(endpoint, username, password, debug)
}

func init() {
	redfish.RegisterApiFactory(&SHuaweiRedfishApiFactory{})
}

type SHuaweiRedfishApi struct {
	generic.SGenericRefishApi
}

func NewHuaweiRedfishApi(endpoint, username, password string, debug bool) redfish.IRedfishDriver {
	api := &SHuaweiRedfishApi{
		SGenericRefishApi: generic.SGenericRefishApi{
			SBaseRedfishClient: redfish.NewBaseRedfishClient(endpoint, username, password, debug),
		},
	}
	api.SetVirtualObject(api)
	return api
}

func (r *SHuaweiRedfishApi) ParseRoot(root jsonutils.JSONObject) error {
	oem, _ := root.Get("Oem")
	if oem == nil {
		return errors.Error("not Huawei iBMC: no Oem field")
	}
	huawei, _ := oem.Get("Huawei")
	if huawei == nil {
		return errors.Error("not Huawei iBMC: no Oem.Huawei field")
	}
	return nil
}

func (r *SHuaweiRedfishApi) GetVirtualCdromInfo(ctx context.Context) (string, redfish.SCdromInfo, error) {
	cdInfo := redfish.SCdromInfo{}
	path, jsonResp, err := r.GetVirtualCdromJSON(ctx)
	if err != nil {
		return "", cdInfo, errors.Wrap(err, "r.GetVirtualCdromJSON")
	}
	imgPath, _ := jsonResp.GetString("Image")
	if imgPath == "null" {
		imgPath = ""
	}
	cdInfo.Image = imgPath
	oem, _ := jsonResp.Get("Oem")
	if oem != nil {
		huawei, _ := oem.Get("Huawei")
		if huawei != nil {
			actions, _ := huawei.Get("Actions")
			if actions != nil {
				cdInfo.SupportAction = true
			}
		}
	}
	return path, cdInfo, nil
}

func (r *SHuaweiRedfishApi) getVmmControlTarget(ctx context.Context, path string) (string, error) {
	resp, err := r.Get(ctx, path)
	if err != nil {
		return "", errors.Wrap(err, "r.Get VirtualMedia")
	}
	target, _ := resp.GetString("Oem", "Huawei", "Actions", "#VirtualMedia.VmmControl", "target")
	if len(target) == 0 {
		return "", errors.Error("VmmControl action target not found")
	}
	return target, nil
}

// getAsyncTaskUrl 从 VmmControl 异步操作的响应中提取可轮询的任务 URL。
// 华为 iBMC 对 POST 返回 HTTP 202 时：
//   - 响应体 @odata.id 是真正的任务资源，如 /redfish/v1/TaskService/Tasks/1，
//     可直接 GET 到含 TaskState 的 JSON；
//   - Location 头指向 SSE 监控流，如 /redfish/v1/TaskService/Tasks/1/Monitor，
//     GET 它返回的是 {"Messages":{...}}，没有 TaskState 字段，轮询会一直超时。
//
// 因此优先使用 @odata.id；仅当 @odata.id 为空时才回退到 Location，
// 并剥离末尾的 /Monitor 后缀得到任务资源 URL。
//
// [AGC:START] tool=Cc date=2026-08-30 author=tangguanghui@tydic.com
func getAsyncTaskUrl(hdr http.Header, resp jsonutils.JSONObject) string {
	if resp != nil {
		if taskUrl, err := resp.GetString("@odata.id"); err == nil && len(taskUrl) > 0 {
			return taskUrl
		}
	}
	if hdr != nil {
		if taskUrl := hdr.Get("Location"); len(taskUrl) > 0 {
			return strings.TrimSuffix(taskUrl, "/Monitor")
		}
	}
	return ""
}

// [AGC:END]

func (r *SHuaweiRedfishApi) MountVirtualCdrom(ctx context.Context, path string, cdromUrl string, boot bool) error {
	r.disableHttpsCertVerification(ctx)
	cdromUrl = r.convertToHttpsUrl(cdromUrl)

	target, err := r.getVmmControlTarget(ctx, path)
	if err != nil {
		return errors.Wrap(err, "getVmmControlTarget")
	}

	disconnParams := jsonutils.NewDict()
	disconnParams.Set("VmmControlType", jsonutils.NewString("Disconnect"))
	dhdr, dresp, derr := r.Post(ctx, target, disconnParams)
	if derr != nil {
		return errors.Wrap(derr, "r.Post VmmControl Disconnect")
	}
	// [AGC:START] tool=Cc date=2026-08-30 author=tangguanghui@tydic.com
	dtaskUrl := getAsyncTaskUrl(dhdr, dresp)
	if len(dtaskUrl) > 0 {
		if err := r.waitVmmTask(ctx, dtaskUrl); err != nil {
			log.Warningf("Huawei VmmControl Disconnect task failed: %v", err)
		}
	}
	// [AGC:END]

	params := jsonutils.NewDict()
	params.Set("VmmControlType", jsonutils.NewString("Connect"))
	params.Set("Image", jsonutils.NewString(cdromUrl))

	hdr, resp, err := r.Post(ctx, target, params)
	if err != nil {
		return errors.Wrap(err, "r.Post VmmControl Connect")
	}
	// [AGC:START] tool=Cc date=2026-08-30 author=tangguanghui@tydic.com
	taskUrl := getAsyncTaskUrl(hdr, resp)
	// [AGC:END]
	err = r.waitVmmTask(ctx, taskUrl)
	if err != nil {
		return errors.Wrap(err, "waitVmmTask Connect")
	}
	if boot {
		err = r.SetNextBootVirtualCdrom(ctx)
		if err != nil {
			return errors.Wrap(err, "r.SetNextBootVirtualCdrom")
		}
	}
	return nil
}

func (r *SHuaweiRedfishApi) waitVmmTask(ctx context.Context, taskUrl string) error {
	if len(taskUrl) == 0 {
		return nil
	}
	for waited := 0; waited < 120; waited += 3 {
		time.Sleep(3 * time.Second)
		resp, err := r.Get(ctx, taskUrl)
		if err != nil {
			return errors.Wrapf(err, "Get task %s", taskUrl)
		}
		state, _ := resp.GetString("TaskState")
		switch state {
		case "Completed":
			log.Infof("Huawei VmmControl task completed")
			return nil
		case "Exception", "Killed":
			msg, _ := resp.GetString("Messages", "Message")
			return errors.Errorf("VmmControl task failed: %s %s", state, msg)
		default:
			log.Debugf("Huawei VmmControl task %s, waited %ds", state, waited)
		}
	}
	return errors.Error("VmmControl task timeout after 120s")
}

func (r *SHuaweiRedfishApi) disableHttpsCertVerification(ctx context.Context) {
	secPath := "/redfish/v1/Managers/1/SecurityService"
	hdr, _, _ := r.GetRequestHeader(ctx, secPath)
	etag := ""
	if hdr != nil {
		etag = hdr.Get("Etag")
		if len(etag) == 0 {
			etag = hdr.Get("ETag")
		}
	}
	params := jsonutils.NewDict()
	params.Set("HttpsTransferCertVerification", jsonutils.JSONFalse)
	patchHeader := http.Header{}
	if len(etag) > 0 {
		patchHeader.Set("If-Match", etag)
	}
	_, _, err := r.PatchWithHeader(ctx, secPath, patchHeader, params)
	if err != nil {
		log.Warningf("disableHttpsCertVerification failed: %v", err)
	} else {
		log.Infof("Huawei iBMC HttpsTransferCertVerification disabled")
	}
}

func (r *SHuaweiRedfishApi) convertToHttpsUrl(cdromUrl string) string {
	parsed, err := url.Parse(cdromUrl)
	if err != nil {
		return cdromUrl
	}
	if parsed.Scheme == "https" {
		return cdromUrl
	}
	host := parsed.Hostname()
	imagePath := strings.TrimPrefix(parsed.Path, "/images/")
	httpsUrl := fmt.Sprintf("https://%s/bm-images/%s", host, imagePath)
	log.Infof("Huawei iBMC convert cdrom URL: %s -> %s", cdromUrl, httpsUrl)
	return httpsUrl
}

func (r *SHuaweiRedfishApi) UmountVirtualCdrom(ctx context.Context, path string) error {
	target, err := r.getVmmControlTarget(ctx, path)
	if err != nil {
		return errors.Wrap(err, "getVmmControlTarget")
	}
	params := jsonutils.NewDict()
	params.Set("VmmControlType", jsonutils.NewString("Disconnect"))

	_, _, err = r.Post(ctx, target, params)
	if err != nil {
		return errors.Wrap(err, "r.Post VmmControl Disconnect")
	}
	return nil
}

func (r *SHuaweiRedfishApi) SetNextBootVirtualCdrom(ctx context.Context) error {
	sysPath, _, err := r.GetResource(ctx, "Systems", "0")
	if err != nil {
		return errors.Wrap(err, "GetResource Systems")
	}
	hdr, _, err := r.GetRequestHeader(ctx, sysPath)
	if err != nil {
		return errors.Wrap(err, "GetRequestHeader for ETag")
	}
	etag := hdr.Get("Etag")
	if len(etag) == 0 {
		etag = hdr.Get("ETag")
	}
	params := jsonutils.NewDict()
	boot := jsonutils.NewDict()
	boot.Set("BootSourceOverrideTarget", jsonutils.NewString("Cd"))
	boot.Set("BootSourceOverrideEnabled", jsonutils.NewString("Once"))
	params.Set("Boot", boot)

	patchHeader := http.Header{}
	if len(etag) > 0 {
		patchHeader.Set("If-Match", etag)
	}
	_, _, err = r.PatchWithHeader(ctx, sysPath, patchHeader, params)
	if err != nil {
		return errors.Wrap(err, "r.PatchWithHeader Boot")
	}
	return nil
}

func (r *SHuaweiRedfishApi) GetVirtualCdromJSON(ctx context.Context) (string, jsonutils.JSONObject, error) {
	_, resp, err := r.GetResource(ctx, "Managers", "0", "VirtualMedia")
	if err != nil {
		return "", nil, errors.Wrap(err, "r.GetResource")
	}
	resp = r.IRedfishDriver().GetParent(resp)
	vmList, err := resp.GetArray(r.IRedfishDriver().MemberKey())
	if err != nil {
		return "", nil, errors.Wrap(err, "get Members")
	}
	for i := len(vmList) - 1; i >= 0; i -= 1 {
		vmPath, _ := vmList[i].GetString(r.IRedfishDriver().LinkKey())
		if len(vmPath) == 0 {
			continue
		}
		if strings.Contains(vmPath, "CD") {
			cdResp, err := r.Get(ctx, vmPath)
			if err == nil && cdResp != nil {
				return vmPath, cdResp, nil
			}
		}
	}
	return "", nil, errors.Error("VirtualMedia CD not found")
}

func (r *SHuaweiRedfishApi) GetSystemLogsPath() string {
	return "/redfish/v1/Managers/1/LogServices/Log1/Entries"
}

func (r *SHuaweiRedfishApi) GetManagerLogsPath() string {
	return "/redfish/v1/Managers/1/LogServices/Log1/Entries"
}

func (r *SHuaweiRedfishApi) GetClearSystemLogsPath() string {
	return "/redfish/v1/Managers/1/LogServices/Log1/Actions/LogService.ClearLog"
}

func (r *SHuaweiRedfishApi) GetClearManagerLogsPath() string {
	return "/redfish/v1/Managers/1/LogServices/Log1/Actions/LogService.ClearLog"
}

func (r *SHuaweiRedfishApi) GetPowerPath() string {
	return "/redfish/v1/Chassis/1/Power"
}

func (r *SHuaweiRedfishApi) GetThermalPath() string {
	return "/redfish/v1/Chassis/1/Thermal"
}

func (r *SHuaweiRedfishApi) GetConsoleJNLP(ctx context.Context) (string, error) {
	log.Warningf("Huawei iBMC does not support JNLP console via Redfish")
	return "", errors.Error("not supported")
}

// [AGC:END]
