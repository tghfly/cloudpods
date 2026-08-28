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

import "testing"

// [AGC:START] tool=Cc date=2026-08-26 author=sniper / 挂载点格式校验单测 /
func TestMountPointReg(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"/data/nfs", true},
		{"/data/cephfs", true},
		{"/", true},
		{" /data/nfs", false},   // 前导空格（实测踩坑：mount exit 32）
		{"/data/nfs ", false},   // 后置空格
		{"data/nfs", false},     // 相对路径
		{"/data/ nfs", false},   // 中间空白
		{"/data/\tnfs", false},  // tab
		{"", false},             // 空
		{"//data", true},        // 连续斜杠（合法但怪，仍放行）
	}
	for _, c := range cases {
		got := mountPointReg.MatchString(c.in)
		if got != c.want {
			t.Errorf("mountPointReg.MatchString(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// [AGC:END]

// [AGC:START] tool=Cc date=2026-08-26 author=sniper / 挂载选项白名单校验单测 /
func TestValidateMountOptions(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"", false},
		{"nfsvers=4.2,hard,timeo=600,rsize=1048576,wsize=1048576", false},
		{"rw,nolock,noatime", false},
		{"nfsvers=4.2, hard, timeo=600", false}, // 带空格合法
		{"nfsvers=3,tcp", true},                // tcp 不在白名单
		{"exec", true},                         // 不在白名单
		{"nfsvers=4.2;rm -rf /", true},         // 注入尝试
		{"rw,,nolock", false},                  // 空段跳过
	}
	for _, c := range cases {
		err := validateMountOptions(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("validateMountOptions(%q) err = %v, wantErr %v", c.in, err, c.wantErr)
		}
	}
}

// [AGC:END]
