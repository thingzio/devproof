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

//go:build !unix

package safefs

import "errors"

// mkfifo is unavailable off unix, which makes the FIFO test skip rather than
// fail. There is no named-pipe equivalent to place in a directory tree here,
// and the behavior under test — refusing a file that is neither regular nor a
// directory — has no way to be provoked.
func mkfifo(string) error { return errors.New("FIFOs are not available on this platform") }
