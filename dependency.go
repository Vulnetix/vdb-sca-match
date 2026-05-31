package match

// Dependency is a single software dependency to be matched against the VDB.
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string
	Purl      string
	Cpe       string
	License   string
	Key       string // unique identifier (e.g. cdxId:name:version or name:version)
}
