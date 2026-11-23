// Package hash implements the digests defined in SPEC §5: streaming file
// digests, skill tree digests and canonical-JSON object digests. Files are
// always hashed in full; nothing is truncated or sampled.
//
// Requirements: LW-FR-04, LW-NFR-02, LW-NFR-04.
package hash
