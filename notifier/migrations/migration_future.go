package migrations

const (
	// This migration drops the key table, as all of its users have been removed.
	//
	// This should only be applied once keymanager removal patches are backported,
	// or 4.1 is out of support.
	_ = `DROP TABLE key;`
)
