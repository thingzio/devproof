// Copyright 2026 Thingz LLC
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
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package safefs

import "errors"

// exclusiveRename is unavailable on this platform.
//
// DP-022 requires failing rather than falling back to a plain rename. A
// fallback would be silently racy on exactly the platform nobody tested, and
// the whole value of staged publication is that a destination either appears
// complete or does not appear.
func exclusiveRename(_, _ string) error {
	return errors.New("atomic exclusive rename is not implemented on this platform")
}

const exclusiveRenameSupported = false
