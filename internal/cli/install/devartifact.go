package install

// The development-artifact checks (the executor digest of the running binary,
// the sibling dev drop, its ownership and checksum document) are owned by
// install/core's devartifact.go and are part of the same artifact pipeline as
// DownloadVerified and VerifyFile.
//
// They are not re-exported here: a development artifact is accepted only by
// the installer's own staging step, and exposing the digest seams would let a
// caller claim bytes the running build never produced.
