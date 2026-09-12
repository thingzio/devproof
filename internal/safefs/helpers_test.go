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

package safefs

import "github.com/thingzio/devproof/internal/canonical"

// canonicalPath converts a test string to a canonical.Path without
// validation, so that a test can hand Open a path the normalizer would have
// rejected and confirm Open refuses it on its own.
func canonicalPath(s string) canonical.Path { return canonical.Path(s) }
