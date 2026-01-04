package version

// These variables are set at build time using ldflags
var (
	Version   = "dev"
	Commit    = "unknown"
	Branch    = "unknown"
	BuildTime = "unknown"
)

// Info returns version information
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Branch    string `json:"branch"`
	BuildTime string `json:"buildTime"`
}

// Get returns the current version info
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		Branch:    Branch,
		BuildTime: BuildTime,
	}
}

