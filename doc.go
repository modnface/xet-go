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
const RustReferenceCommit = "7a267506b77b484688654c46079e3aec35394611"
