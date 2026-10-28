package spec

// StageTarget is the release record the Hub stamped onto one pending
// config.stage row: the version and the pinned manifest digest the node should
// converge to. It is deliberately not a task parameter — config.* params stay
// frozen — so the Agent reads it over the outbound Hub boundary. The type lives
// in the pure domain because both the Hub client and the Agent runtime speak
// it.
type StageTarget struct {
	Version        string
	ManifestSHA256 string
}
