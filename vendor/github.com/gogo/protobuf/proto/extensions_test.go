// Go support for Protocol Buffers - Google's data interchange format
//
// Copyright 2014 The Go Authors.  All rights reserved.
// https://github.com/golang/protobuf
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package proto_test

import (
	"testing"

	"github.com/gogo/protobuf/proto"
	pb "github.com/gogo/protobuf/proto/testdata"
)

func TestGetExtensionsWithMissingExtensions(t *testing.T) {
	msg := &pb.MyMessage{}
	ext1 := &pb.Ext{}
	if err := proto.SetExtension(msg, pb.E_Ext_More, ext1); err != nil {
		t.Fatalf("Could not set ext1: %s", ext1)
	}
	exts, err := proto.GetExtensions(msg, []*proto.ExtensionDesc{
		pb.E_Ext_More,
		pb.E_Ext_Text,
	})
	if err != nil {
		t.Fatalf("GetExtensions() failed: %s", err)
	}
	if exts[0] != ext1 {
		t.Errorf("ext1 not in returned extensions: %T %v", exts[0], exts[0])
	}
	if exts[1] != nil {
		t.Errorf("ext2 in returned extensions: %T %v", exts[1], exts[1])
	}
}

func TestGetExtensionStability(t *testing.T) {
	check := func(m *pb.MyMessage) bool {
		ext1, err := proto.GetExtension(m, pb.E_Ext_More)
		if err != nil {
			t.Fatalf("GetExtension() failed: %s", err)
		}
		ext2, err := proto.GetExtension(m, pb.E_Ext_More)
		if err != nil {
			t.Fatalf("GetExtension() failed: %s", err)
		}
		return ext1 == ext2
	}
	msg := &pb.MyMessage{Count: proto.Int32(4)}
	ext0 := &pb.Ext{}
	if err := proto.SetExtension(msg, pb.E_Ext_More, ext0); err != nil {
		t.Fatalf("Could not set ext1: %s", ext0)
	}
	if !check(msg) {
		t.Errorf("GetExtension() not stable before marshaling")
	}
	bb, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal() failed: %s", err)
	}
	msg1 := &pb.MyMessage{}
	err = proto.Unmarshal(bb, msg1)
	if err != nil {
		t.Fatalf("Unmarshal() failed: %s", err)
	}
	if !check(msg1) {
		t.Errorf("GetExtension() not stable after unmarshaling")
	}
}

func TestExtensionsRoundTrip(t *testing.T) {
	msg := &pb.MyMessage{}
	ext1 := &pb.Ext{
		Data: proto.String("hi"),
	}
	ext2 := &pb.Ext{
		Data: proto.String("there"),
	}
	exists := proto.HasExtension(msg, pb.E_Ext_More)
	if exists {
		t.Error("Extension More present unexpectedly")
	}
	if err := proto.SetExtension(msg, pb.E_Ext_More, ext1); err != nil {
		t.Error(err)
	}
	if err := proto.SetExtension(msg, pb.E_Ext_More, ext2); err != nil {
		t.Error(err)
	}
	e, err := proto.GetExtension(msg, pb.E_Ext_More)
	if err != nil {
		t.Error(err)
	}
	x, ok := e.(*pb.Ext)
	if !ok {
		t.Errorf("e has type %T, expected testdata.Ext", e)
	} else if *x.Data != "there" {
		t.Errorf("SetExtension failed to overwrite, got %+v, not 'there'", x)
	}
	proto.ClearExtension(msg, pb.E_Ext_More)
	if _, err = proto.GetExtension(msg, pb.E_Ext_More); err != proto.ErrMissingExtension {
		t.Errorf("got %v, expected ErrMissingExtension", e)
	}
	if _, err := proto.GetExtension(msg, pb.E_X215); err == nil {
		t.Error("expected bad extension error, got nil")
	}
	if err := proto.SetExtension(msg, pb.E_X215, 12); err == nil {
		t.Error("expected extension err")
	}
	if err := proto.SetExtension(msg, pb.E_Ext_More, 12); err == nil {
		t.Error("expected some sort of type mismatch error, got nil")
	}
}

func TestNilExtension(t *testing.T) {
	msg := &pb.MyMessage{
		Count: proto.Int32(1),
	}
	if err := proto.SetExtension(msg, pb.E_Ext_Text, proto.String("hello")); err != nil {
		t.Fatal(err)
	}
	if err := proto.SetExtension(msg, pb.E_Ext_More, (*pb.Ext)(nil)); err == nil {
		t.Error("expected SetExtension to fail due to a nil extension")
	} else if want := "proto: SetExtension called with nil value of type *testdata.Ext"; err.Error() != want {
		t.Errorf("expected error %v, got %v", want, err)
	}
	// Note: if the behavior of Marshal is ever changed to ignore nil extensions, update
	// this test to verify that E_Ext_Text is properly propagated through marshal->unmarshal.
}
