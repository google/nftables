// Copyright 2018 Google LLC. All Rights Reserved.
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

// Package binaryutil contains convenience wrappers around encoding/binary.
package binaryutil

import (
	"encoding/binary"

	"github.com/koneu/natend"
)

// ByteOrder is like binary.ByteOrder, but allocates memory and returns byte
// slices, for convenience.
type ByteOrder interface {
	PutUint16(v uint16) []byte
	PutUint32(v uint32) []byte
}

// NativeEndian is either little endian or big endian, depending on the native
// endian-ness, and allocates memory and returns byte slices, for convenience.
var NativeEndian ByteOrder = &nativeEndian{}

type nativeEndian struct{}

func (nativeEndian) PutUint16(v uint16) []byte {
	buf := make([]byte, 2)
	natend.NativeEndian.PutUint16(buf, v)
	return buf
}

func (nativeEndian) PutUint32(v uint32) []byte {
	buf := make([]byte, 4)
	natend.NativeEndian.PutUint32(buf, v)
	return buf
}

// BigEndian is like binary.BigEndian, but allocates memory and returns byte
// slices, for convenience.
var BigEndian ByteOrder = &bigEndian{}

type bigEndian struct{}

func (bigEndian) PutUint16(v uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	return buf
}

func (bigEndian) PutUint32(v uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	return buf
}
