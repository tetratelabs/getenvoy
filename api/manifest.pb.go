// Copyright 2021 Tetrate
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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.15.2
// source: api/manifest.proto

package api

import (
	reflect "reflect"
	sync "sync"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Compliances should be single word, no underscores
type Compliance int32

const (
	Compliance_FIPS1402 Compliance = 0
)

// Enum value maps for Compliance.
var (
	Compliance_name = map[int32]string{
		0: "FIPS1402",
	}
	Compliance_value = map[string]int32{
		"FIPS1402": 0,
	}
)

func (x Compliance) Enum() *Compliance {
	p := new(Compliance)
	*p = x
	return p
}

func (x Compliance) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Compliance) Descriptor() protoreflect.EnumDescriptor {
	return file_api_manifest_proto_enumTypes[0].Descriptor()
}

func (Compliance) Type() protoreflect.EnumType {
	return &file_api_manifest_proto_enumTypes[0]
}

func (x Compliance) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Compliance.Descriptor instead.
func (Compliance) EnumDescriptor() ([]byte, []int) {
	return file_api_manifest_proto_rawDescGZIP(), []int{0}
}

// Default must be unknown in order to sort correctly
type Build_Platform int32

const (
	Build_UNKNOWN     Build_Platform = 0
	Build_DARWIN      Build_Platform = 1
	Build_WINDOWS     Build_Platform = 2
	Build_LINUX_GLIBC Build_Platform = 3
)

// Enum value maps for Build_Platform.
var (
	Build_Platform_name = map[int32]string{
		0: "UNKNOWN",
		1: "DARWIN",
		2: "WINDOWS",
		3: "LINUX_GLIBC",
	}
	Build_Platform_value = map[string]int32{
		"UNKNOWN":     0,
		"DARWIN":      1,
		"WINDOWS":     2,
		"LINUX_GLIBC": 3,
	}
)

func (x Build_Platform) Enum() *Build_Platform {
	p := new(Build_Platform)
	*p = x
	return p
}

func (x Build_Platform) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Build_Platform) Descriptor() protoreflect.EnumDescriptor {
	return file_api_manifest_proto_enumTypes[1].Descriptor()
}

func (Build_Platform) Type() protoreflect.EnumType {
	return &file_api_manifest_proto_enumTypes[1]
}

func (x Build_Platform) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Build_Platform.Descriptor instead.
func (Build_Platform) EnumDescriptor() ([]byte, []int) {
	return file_api_manifest_proto_rawDescGZIP(), []int{3, 0}
}

type Manifest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ManifestVersion string `protobuf:"bytes,1,opt,name=manifest_version,json=manifestVersion,proto3" json:"manifest_version,omitempty"`
	// Key is the flavor name
	Flavors map[string]*Flavor `protobuf:"bytes,2,rep,name=flavors,proto3" json:"flavors,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Manifest) Reset() {
	*x = Manifest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_manifest_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Manifest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Manifest) ProtoMessage() {}

func (x *Manifest) ProtoReflect() protoreflect.Message {
	mi := &file_api_manifest_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Manifest.ProtoReflect.Descriptor instead.
func (*Manifest) Descriptor() ([]byte, []int) {
	return file_api_manifest_proto_rawDescGZIP(), []int{0}
}

func (x *Manifest) GetManifestVersion() string {
	if x != nil {
		return x.ManifestVersion
	}
	return ""
}

func (x *Manifest) GetFlavors() map[string]*Flavor {
	if x != nil {
		return x.Flavors
	}
	return nil
}

type Flavor struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Name is the composite key of the value's filter_profile and compliance
	// Format: filter_profile or filter_profile-compliance1-compliance2
	// Examples: standard, istio-fips1402
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Filter profile is the name of the collection of filters
	// Examples: standard, istio, minimal
	FilterProfile string `protobuf:"bytes,2,opt,name=filter_profile,json=filterProfile,proto3" json:"filter_profile,omitempty"`
	// All filters available in this flavor
	Filters []string `protobuf:"bytes,3,rep,name=filters,proto3" json:"filters,omitempty"`
	// Compliance requirements met by this flavor
	Compliances []Compliance `protobuf:"varint,4,rep,packed,name=compliances,proto3,enum=api.Compliance" json:"compliances,omitempty"`
	// Key is the version's name
	Versions map[string]*Version `protobuf:"bytes,5,rep,name=versions,proto3" json:"versions,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Flavor) Reset() {
	*x = Flavor{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_manifest_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Flavor) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Flavor) ProtoMessage() {}

func (x *Flavor) ProtoReflect() protoreflect.Message {
	mi := &file_api_manifest_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Flavor.ProtoReflect.Descriptor instead.
func (*Flavor) Descriptor() ([]byte, []int) {
	return file_api_manifest_proto_rawDescGZIP(), []int{1}
}

func (x *Flavor) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Flavor) GetFilterProfile() string {
	if x != nil {
		return x.FilterProfile
	}
	return ""
}

func (x *Flavor) GetFilters() []string {
	if x != nil {
		return x.Filters
	}
	return nil
}

func (x *Flavor) GetCompliances() []Compliance {
	if x != nil {
		return x.Compliances
	}
	return nil
}

func (x *Flavor) GetVersions() map[string]*Version {
	if x != nil {
		return x.Versions
	}
	return nil
}

type Version struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Name is the Envoy version
	// Examples: 1.10.0, 1.11.0, nightly
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Key is the build's platform
	Builds map[string]*Build `protobuf:"bytes,5,rep,name=builds,proto3" json:"builds,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Version) Reset() {
	*x = Version{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_manifest_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Version) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Version) ProtoMessage() {}

func (x *Version) ProtoReflect() protoreflect.Message {
	mi := &file_api_manifest_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Version.ProtoReflect.Descriptor instead.
func (*Version) Descriptor() ([]byte, []int) {
	return file_api_manifest_proto_rawDescGZIP(), []int{2}
}

func (x *Version) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Version) GetBuilds() map[string]*Build {
	if x != nil {
		return x.Builds
	}
	return nil
}

type Build struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Platform            Build_Platform `protobuf:"varint,1,opt,name=platform,proto3,enum=api.Build_Platform" json:"platform,omitempty"`
	DownloadLocationUrl string         `protobuf:"bytes,2,opt,name=download_location_url,json=downloadLocationUrl,proto3" json:"download_location_url,omitempty"`
}

func (x *Build) Reset() {
	*x = Build{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_manifest_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Build) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Build) ProtoMessage() {}

func (x *Build) ProtoReflect() protoreflect.Message {
	mi := &file_api_manifest_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Build.ProtoReflect.Descriptor instead.
func (*Build) Descriptor() ([]byte, []int) {
	return file_api_manifest_proto_rawDescGZIP(), []int{3}
}

func (x *Build) GetPlatform() Build_Platform {
	if x != nil {
		return x.Platform
	}
	return Build_UNKNOWN
}

func (x *Build) GetDownloadLocationUrl() string {
	if x != nil {
		return x.DownloadLocationUrl
	}
	return ""
}

var File_api_manifest_proto protoreflect.FileDescriptor

var file_api_manifest_proto_rawDesc = []byte{
	0x0a, 0x12, 0x61, 0x70, 0x69, 0x2f, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x03, 0x61, 0x70, 0x69, 0x22, 0xb4, 0x01, 0x0a, 0x08, 0x4d, 0x61,
	0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x12, 0x29, 0x0a, 0x10, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65,
	0x73, 0x74, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0f, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x12, 0x34, 0x0a, 0x07, 0x66, 0x6c, 0x61, 0x76, 0x6f, 0x72, 0x73, 0x18, 0x02, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x4d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73,
	0x74, 0x2e, 0x46, 0x6c, 0x61, 0x76, 0x6f, 0x72, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x07,
	0x66, 0x6c, 0x61, 0x76, 0x6f, 0x72, 0x73, 0x1a, 0x47, 0x0a, 0x0c, 0x46, 0x6c, 0x61, 0x76, 0x6f,
	0x72, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x21, 0x0a, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0b, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x46,
	0x6c, 0x61, 0x76, 0x6f, 0x72, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01,
	0x22, 0x92, 0x02, 0x0a, 0x06, 0x46, 0x6c, 0x61, 0x76, 0x6f, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12,
	0x25, 0x0a, 0x0e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x5f, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x50,
	0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72,
	0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73,
	0x12, 0x31, 0x0a, 0x0b, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x73, 0x18,
	0x04, 0x20, 0x03, 0x28, 0x0e, 0x32, 0x0f, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x43, 0x6f, 0x6d, 0x70,
	0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x52, 0x0b, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x69, 0x61, 0x6e,
	0x63, 0x65, 0x73, 0x12, 0x35, 0x0a, 0x08, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x18,
	0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x46, 0x6c, 0x61, 0x76,
	0x6f, 0x72, 0x2e, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79,
	0x52, 0x08, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x1a, 0x49, 0x0a, 0x0d, 0x56, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x22, 0x0a,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x61,
	0x70, 0x69, 0x2e, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x96, 0x01, 0x0a, 0x07, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x30, 0x0a, 0x06, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x73, 0x18,
	0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x56, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x2e, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52,
	0x06, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x73, 0x1a, 0x45, 0x0a, 0x0b, 0x42, 0x75, 0x69, 0x6c, 0x64,
	0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x20, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x42, 0x75,
	0x69, 0x6c, 0x64, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0xaf,
	0x01, 0x0a, 0x05, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x12, 0x2f, 0x0a, 0x08, 0x70, 0x6c, 0x61, 0x74,
	0x66, 0x6f, 0x72, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x13, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x2e, 0x50, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x52,
	0x08, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x12, 0x32, 0x0a, 0x15, 0x64, 0x6f, 0x77,
	0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x5f, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x75,
	0x72, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x13, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f,
	0x61, 0x64, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x55, 0x72, 0x6c, 0x22, 0x41, 0x0a,
	0x08, 0x50, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x12, 0x0b, 0x0a, 0x07, 0x55, 0x4e, 0x4b,
	0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06, 0x44, 0x41, 0x52, 0x57, 0x49, 0x4e,
	0x10, 0x01, 0x12, 0x0b, 0x0a, 0x07, 0x57, 0x49, 0x4e, 0x44, 0x4f, 0x57, 0x53, 0x10, 0x02, 0x12,
	0x0f, 0x0a, 0x0b, 0x4c, 0x49, 0x4e, 0x55, 0x58, 0x5f, 0x47, 0x4c, 0x49, 0x42, 0x43, 0x10, 0x03,
	0x2a, 0x1a, 0x0a, 0x0a, 0x43, 0x6f, 0x6d, 0x70, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x12, 0x0c,
	0x0a, 0x08, 0x46, 0x49, 0x50, 0x53, 0x31, 0x34, 0x30, 0x32, 0x10, 0x00, 0x42, 0x29, 0x5a, 0x27,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x74, 0x65, 0x74, 0x72, 0x61,
	0x74, 0x65, 0x6c, 0x61, 0x62, 0x73, 0x2f, 0x67, 0x65, 0x74, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f,
	0x61, 0x70, 0x69, 0x3b, 0x61, 0x70, 0x69, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_manifest_proto_rawDescOnce sync.Once
	file_api_manifest_proto_rawDescData = file_api_manifest_proto_rawDesc
)

func file_api_manifest_proto_rawDescGZIP() []byte {
	file_api_manifest_proto_rawDescOnce.Do(func() {
		file_api_manifest_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_manifest_proto_rawDescData)
	})
	return file_api_manifest_proto_rawDescData
}

var file_api_manifest_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_api_manifest_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_api_manifest_proto_goTypes = []interface{}{
	(Compliance)(0),     // 0: api.Compliance
	(Build_Platform)(0), // 1: api.Build.Platform
	(*Manifest)(nil),    // 2: api.Manifest
	(*Flavor)(nil),      // 3: api.Flavor
	(*Version)(nil),     // 4: api.Version
	(*Build)(nil),       // 5: api.Build
	nil,                 // 6: api.Manifest.FlavorsEntry
	nil,                 // 7: api.Flavor.VersionsEntry
	nil,                 // 8: api.Version.BuildsEntry
}
var file_api_manifest_proto_depIdxs = []int32{
	6, // 0: api.Manifest.flavors:type_name -> api.Manifest.FlavorsEntry
	0, // 1: api.Flavor.compliances:type_name -> api.Compliance
	7, // 2: api.Flavor.versions:type_name -> api.Flavor.VersionsEntry
	8, // 3: api.Version.builds:type_name -> api.Version.BuildsEntry
	1, // 4: api.Build.platform:type_name -> api.Build.Platform
	3, // 5: api.Manifest.FlavorsEntry.value:type_name -> api.Flavor
	4, // 6: api.Flavor.VersionsEntry.value:type_name -> api.Version
	5, // 7: api.Version.BuildsEntry.value:type_name -> api.Build
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_api_manifest_proto_init() }
func file_api_manifest_proto_init() {
	if File_api_manifest_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_manifest_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Manifest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_manifest_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Flavor); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_manifest_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Version); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_manifest_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Build); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_manifest_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_api_manifest_proto_goTypes,
		DependencyIndexes: file_api_manifest_proto_depIdxs,
		EnumInfos:         file_api_manifest_proto_enumTypes,
		MessageInfos:      file_api_manifest_proto_msgTypes,
	}.Build()
	File_api_manifest_proto = out.File
	file_api_manifest_proto_rawDesc = nil
	file_api_manifest_proto_goTypes = nil
	file_api_manifest_proto_depIdxs = nil
}
