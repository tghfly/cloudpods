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

package megactl

import (
	"fmt"
	"strings"

	"yunion.io/x/log"
	"yunion.io/x/pkg/errors"

	api "yunion.io/x/onecloud/pkg/apis/compute"
	"yunion.io/x/onecloud/pkg/baremetal/utils/raid"
	"yunion.io/x/onecloud/pkg/compute/baremetal"
)

func storcliIsJBODEnabled(
	getCmd func(args ...string) (string, error),
	term raid.IExecTerm,
) bool {
	cmd, err := getCmd("show", "jbod")
	if err != nil {
		log.Errorf("get storcli controller cmd: %v", err)
		return false
	}
	lines, err := term.Run(cmd)
	if err != nil {
		log.Errorf("storcliIsJBODEnabled error: %s", err)
		return false
	}
	for _, line := range lines {
		line = strings.ToLower(line)
		if strings.HasPrefix(line, "jbod") {
			data := strings.Split(line, " ")
			if strings.TrimSpace(data[len(data)-1]) == "on" {
				return true
			}
			return false
		}
	}
	return false
}

func storcliEnableJBOD(
	getCmd func(args ...string) (string, error),
	term raid.IExecTerm,
	enable bool) bool {
	val := "off"
	if enable {
		val = "on"
	}
	cmd, err := getCmd("set", fmt.Sprintf("jbod=%s", val), "force")
	if err != nil {
		log.Errorf("get storcli controller cmd: %v", err)
		return false
	}
	_, err = term.Run(cmd)
	if err != nil {
		log.Errorf("EnableJBOD %v fail: %v", enable, err)
		return false
	}
	return true
}

// [AI:START] tool=claude author=tangguanghui@tydic.com
// storcliGetPDStates 通过 storcli 的 JSON 输出查询所有物理盘的当前状态,
// 返回 map 的 key 为 "EID:Slt"(如 "32:0"),value 为状态字符串
func storcliGetPDStates(
	getCmd func(args ...string) (string, error),
	term raid.IExecTerm,
) (map[string]string, error) {
	cmd, err := getCmd("eall/sall", "show", "J")
	if err != nil {
		return nil, errors.Wrap(err, "get storcli PD list cmd")
	}
	lines, err := term.Run(cmd)
	if err != nil {
		return nil, errors.Wrap(err, "run storcli eall/sall show J")
	}
	info, err := parseStorcliControllers(strings.Join(lines, "\n"))
	if err != nil {
		return nil, errors.Wrap(err, "parseStorcliControllers")
	}
	states := make(map[string]string)
	for _, c := range info.Controllers {
		for _, pd := range c.ResponseData.Info {
			states[pd.EnclosureIdSlotNo] = pd.State
		}
	}
	return states, nil
}

// [AI:END]

// [AI:START] tool=claude author=tangguanghui@tydic.com
// isStorcliPDJBOD 判断盘状态是否为 JBOD,
// 使用包含匹配以兼容 "JBOD, Spun Down" 等变体
func isStorcliPDJBOD(state string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(state)), "jbod")
}

// [AI:END]

// [AI:START] tool=claude author=tangguanghui@tydic.com
// storcliBuildJBOD 将未配置的盘转为 JBOD 直通模式。
// 已处于 JBOD 态的盘直接跳过:固件对这类盘执行 "set jbod" 会报
// "Operation not allowed"(如盘状态转换配额耗尽时),
// 且 JBOD -> UGood -> JBOD 的往返转换只会白白消耗固件配额。
// 这里只关心最终状态,因此 "set jbod" 失败后若复查确认盘已是
// JBOD 态,同样视为成功
func storcliBuildJBOD(
	getCmd func(args ...string) (string, error),
	term raid.IExecTerm,
	devs []*baremetal.BaremetalStorage) error {
	if !storcliIsJBODEnabled(getCmd, term) {
		storcliEnableJBOD(getCmd, term, true)
		storcliEnableJBOD(getCmd, term, false)
		storcliEnableJBOD(getCmd, term, true)
	}
	if !storcliIsJBODEnabled(getCmd, term) {
		return fmt.Errorf("JBOD not supported")
	}
	// devIsJBOD 用 "enclosure:slot" 作为 key 在盘状态 map 中查询指定盘是否已 JBOD
	devIsJBOD := func(d *baremetal.BaremetalStorage, states map[string]string) bool {
		if states == nil {
			return false
		}
		state, ok := states[GetSpecString(d)]
		return ok && isStorcliPDJBOD(state)
	}
	states, err := storcliGetPDStates(getCmd, term)
	if err != nil {
		// 状态查询是尽力而为,失败时回退为直接下发 set jbod
		log.Warningf("storcliBuildJBOD: get PD states: %v", err)
		states = nil
	}
	errs := make([]error, 0)
	for _, d := range devs {
		if devIsJBOD(d, states) {
			log.Infof("storcliBuildJBOD: dev %s already JBOD, skip", GetSpecString(d))
			continue
		}
		cmd, err := getCmd()
		if err != nil {
			return errors.Wrapf(err, "getCmd for dev %#v", d)
		}
		cmd = fmt.Sprintf("%s/e%d/s%d set jbod", cmd, d.Enclosure, d.Slot)
		if _, err := term.Run(cmd); err != nil {
			// 盘已是 JBOD 态时固件会拒绝 "set jbod" 并报
			// "Operation not allowed"(如盘状态转换计数器耗尽),
			// 失败后先复查盘状态,确认已 JBOD 则不算错误
			if newStates, err2 := storcliGetPDStates(getCmd, term); err2 == nil && devIsJBOD(d, newStates) {
				log.Infof("storcliBuildJBOD: dev %s already JBOD after set jbod fail", GetSpecString(d))
				continue
			}
			errs = append(errs, errors.Wrapf(err, "set jbod cmd %s", cmd))
		}
	}
	return errors.NewAggregate(errs)
}

// [AI:END]

func storcliBuildNoRaid(
	getCmd func(args ...string) (string, error),
	term raid.IExecTerm,
	devs []*baremetal.BaremetalStorage) error {
	err := storcliBuildJBOD(getCmd, term, devs)
	if err == nil {
		return nil
	}
	log.Errorf("Try storcli build JBOD fail: %v", err)
	labels := []string{}
	for _, dev := range devs {
		labels = append(labels, GetSpecString(dev))
	}
	args := []string{
		"add", "vd", "each", "type=raid0",
		fmt.Sprintf("drives=%s", strings.Join(labels, ",")),
		"wt", "nora", "direct",
	}
	cmd, err := getCmd(args...)
	if err != nil {
		return errors.Wrapf(err, "build none raid")
	}
	_, err = term.Run(cmd)
	return err
}

func storcliClearJBODDisks(
	getCmd func(args ...string) (string, error),
	term raid.IExecTerm,
	devs []*MegaRaidPhyDev,
) error {
	errs := make([]error, 0)
	for _, dev := range devs {
		cmd, err := getCmd()
		if err != nil {
			return errors.Wrap(err, "get cmd error")
		}
		cmd = fmt.Sprintf("%s/e%d/s%d set good force", cmd, dev.enclosure, dev.slot)
		if _, err := term.Run(cmd); err != nil {
			err = errors.Wrapf(err, "Set PD good storcli cmd %v", cmd)
			errs = append(errs, err)
		}
	}
	return errors.NewAggregate(errs)
}

func storcliBuildRaid(
	getCmd func(args ...string) (string, error),
	term raid.IExecTerm,
	devs []*baremetal.BaremetalStorage,
	conf *api.BaremetalDiskConfig,
	level uint,
) error {
	args := []string{}
	args = append(args, "add", "vd", fmt.Sprintf("type=r%d", level))
	args = append(args, conf2ParamsStorcliSize(conf)...)
	labels := []string{}
	for _, dev := range devs {
		labels = append(labels, GetSpecString(dev))
	}
	args = append(args, fmt.Sprintf("drives=%s", strings.Join(labels, ",")))
	if level == 10 {
		args = append(args, "PDperArray=2")
	}
	args = append(args, conf2ParamsStorcli(conf)...)
	cmd, err := getCmd(args...)
	if err != nil {
		return errors.Wrapf(err, "build raid %d", level)
	}
	if _, err := term.Run(cmd); err != nil {
		return err
	}
	return nil
}

func conf2ParamsStorcliSize(conf *api.BaremetalDiskConfig) []string {
	params := []string{}
	szStr := []string{}
	if len(conf.Size) > 0 {
		for _, sz := range conf.Size {
			szStr = append(szStr, fmt.Sprintf("%dMB", sz))
		}
		params = append(params, fmt.Sprintf("Size=%s", strings.Join(szStr, ",")))
	}
	return params
}

func conf2ParamsStorcli(conf *api.BaremetalDiskConfig) []string {
	params := []string{}
	if conf.WT != nil {
		if *conf.WT {
			params = append(params, "wt")
		} else {
			params = append(params, "wb")
		}
	}
	if conf.RA != nil {
		if *conf.RA {
			params = append(params, "ra")
		} else {
			params = append(params, "nora")
		}
	}
	if conf.Direct != nil {
		if *conf.Direct {
			params = append(params, "direct")
		} else {
			params = append(params, "cached")
		}
	}
	if conf.Cachedbadbbu != nil {
		if *conf.Cachedbadbbu {
			params = append(params, "CachedBadBBU")
		} else {
			params = append(params, "NoCachedBadBBU")
		}
	}
	if conf.Strip != nil {
		params = append(params, fmt.Sprintf("Strip=%d", *conf.Strip))
	}
	return params
}
