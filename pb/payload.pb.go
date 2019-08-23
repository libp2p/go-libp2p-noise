// Code generated by protoc-gen-go. DO NOT EDIT.
// source: payload.proto

package noise

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type NoiseHandshakePayload struct {
	Libp2PKey               []byte   `protobuf:"bytes,1,opt,name=libp2p_key,json=libp2pKey,proto3" json:"libp2p_key,omitempty"`
	NoiseStaticKeySignature []byte   `protobuf:"bytes,2,opt,name=noise_static_key_signature,json=noiseStaticKeySignature,proto3" json:"noise_static_key_signature,omitempty"`
	Libp2PData              []byte   `protobuf:"bytes,3,opt,name=libp2p_data,json=libp2pData,proto3" json:"libp2p_data,omitempty"`
	Libp2PDataSignature     []byte   `protobuf:"bytes,4,opt,name=libp2p_data_signature,json=libp2pDataSignature,proto3" json:"libp2p_data_signature,omitempty"`
	XXX_NoUnkeyedLiteral    struct{} `json:"-"`
	XXX_unrecognized        []byte   `json:"-"`
	XXX_sizecache           int32    `json:"-"`
}

func (m *NoiseHandshakePayload) Reset()         { *m = NoiseHandshakePayload{} }
func (m *NoiseHandshakePayload) String() string { return proto.CompactTextString(m) }
func (*NoiseHandshakePayload) ProtoMessage()    {}
func (*NoiseHandshakePayload) Descriptor() ([]byte, []int) {
	return fileDescriptor_678c914f1bee6d56, []int{0}
}

func (m *NoiseHandshakePayload) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NoiseHandshakePayload.Unmarshal(m, b)
}
func (m *NoiseHandshakePayload) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NoiseHandshakePayload.Marshal(b, m, deterministic)
}
func (m *NoiseHandshakePayload) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NoiseHandshakePayload.Merge(m, src)
}
func (m *NoiseHandshakePayload) XXX_Size() int {
	return xxx_messageInfo_NoiseHandshakePayload.Size(m)
}
func (m *NoiseHandshakePayload) XXX_DiscardUnknown() {
	xxx_messageInfo_NoiseHandshakePayload.DiscardUnknown(m)
}

var xxx_messageInfo_NoiseHandshakePayload proto.InternalMessageInfo

func (m *NoiseHandshakePayload) GetLibp2PKey() []byte {
	if m != nil {
		return m.Libp2PKey
	}
	return nil
}

func (m *NoiseHandshakePayload) GetNoiseStaticKeySignature() []byte {
	if m != nil {
		return m.NoiseStaticKeySignature
	}
	return nil
}

func (m *NoiseHandshakePayload) GetLibp2PData() []byte {
	if m != nil {
		return m.Libp2PData
	}
	return nil
}

func (m *NoiseHandshakePayload) GetLibp2PDataSignature() []byte {
	if m != nil {
		return m.Libp2PDataSignature
	}
	return nil
}

func init() {
	proto.RegisterType((*NoiseHandshakePayload)(nil), "noise.NoiseHandshakePayload")
}

func init() { proto.RegisterFile("payload.proto", fileDescriptor_678c914f1bee6d56) }

var fileDescriptor_678c914f1bee6d56 = []byte{
	// 176 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x2d, 0x48, 0xac, 0xcc,
	0xc9, 0x4f, 0x4c, 0xd1, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0xcd, 0xcb, 0xcf, 0x2c, 0x4e,
	0x55, 0x3a, 0xc1, 0xc8, 0x25, 0xea, 0x07, 0x62, 0x79, 0x24, 0xe6, 0xa5, 0x14, 0x67, 0x24, 0x66,
	0xa7, 0x06, 0x40, 0x94, 0x09, 0xc9, 0x72, 0x71, 0xe5, 0x64, 0x26, 0x15, 0x18, 0x15, 0xc4, 0x67,
	0xa7, 0x56, 0x4a, 0x30, 0x2a, 0x30, 0x6a, 0xf0, 0x04, 0x71, 0x42, 0x44, 0xbc, 0x53, 0x2b, 0x85,
	0xac, 0xb9, 0xa4, 0xc0, 0x26, 0xc4, 0x17, 0x97, 0x24, 0x96, 0x64, 0x26, 0x83, 0x14, 0xc5, 0x17,
	0x67, 0xa6, 0xe7, 0x25, 0x96, 0x94, 0x16, 0xa5, 0x4a, 0x30, 0x81, 0x95, 0x8b, 0x83, 0x55, 0x04,
	0x83, 0x15, 0x78, 0xa7, 0x56, 0x06, 0xc3, 0xa4, 0x85, 0xe4, 0xb9, 0xb8, 0xa1, 0x66, 0xa7, 0x24,
	0x96, 0x24, 0x4a, 0x30, 0x83, 0x55, 0x43, 0xad, 0x73, 0x49, 0x2c, 0x49, 0x14, 0x32, 0xe2, 0x12,
	0x45, 0x52, 0x80, 0x64, 0x30, 0x0b, 0x58, 0xa9, 0x30, 0x42, 0x29, 0xdc, 0xd0, 0x24, 0x36, 0xb0,
	0xc7, 0x8c, 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0x0f, 0xcc, 0x4e, 0xb9, 0xe9, 0x00, 0x00, 0x00,
}