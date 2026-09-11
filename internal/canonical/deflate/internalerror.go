// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package deflate

// Extracted verbatim from the standard library's inflate.go. Only the
// encoder is frozen here — decompressing a valid DEFLATE stream is
// unambiguous, so reading may use any correct implementation — but the
// encoder references this one declaration from the decoder's file.

// An InternalError reports an error in the flate code itself.
type InternalError string

func (e InternalError) Error() string { return "flate: internal error: " + string(e) }
