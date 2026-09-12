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

package devproof

// unlinkWhileOpen reports whether the platform allows removing a file's
// directory entry while a handle to it is still open.
//
// False on Windows, which fails such a remove with a sharing violation. The
// staging file therefore keeps its name until it is closed, so an abrupt
// termination can leave one behind in the temporary directory.
const unlinkWhileOpen = false
