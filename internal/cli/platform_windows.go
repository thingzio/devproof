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

//go:build windows

package cli

// executableBitObservable reports whether the filesystem can tell an
// executable file from a non-executable one.
//
// False on Windows: os.Stat synthesizes a mode of 0666, or 0444 when the
// read-only attribute is set, and never reports an execute bit. NTFS has no
// equivalent — executability there is a property of the file extension and of
// ACLs, not of a permission bit the portable profile could read.
const executableBitObservable = false
