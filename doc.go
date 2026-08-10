// Package xet implements the hosting-decoupled Xet data plane.
//
// It provides deterministic Xet formats and identities, a client for the Xet
// CAS HTTP protocol, and streaming upload and reconstruction operations.
// Repository discovery, hosting authentication, and repository commits are
// deliberately outside this module.
package xet

// ProtocolVersion is the Xet specification version targeted by this module.
const ProtocolVersion = "1.1.0"

// RustReferenceCommit is the official xet-core revision used for differential
// conformance testing.
const RustReferenceCommit = "de71453d952bd8b806edaa997c72313051a49050"
