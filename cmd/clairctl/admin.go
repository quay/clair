package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/Masterminds/semver"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/claircore"
	"github.com/quay/zlog"
	"github.com/urfave/cli/v2"
)

// AdminCmd is the "admin" subcommand.
var AdminCmd = &cli.Command{
	Name:        "admin",
	Description: "Various administrator tasks. May require additional privileges, cause data loss, or frighten small children.",
	Usage:       "run administrator task",
	Flags:       []cli.Flag{},
	Category:    "Advanced",
	Subcommands: []*cli.Command{
		{
			Name:        "pre",
			Description: "Tasks that can be run in preparation for a Clair version",
			Usage:       "run pre-upgrade task",
			ArgsUsage:   "\b",
			Subcommands: []*cli.Command{
				{
					Name:    "v4.7.0",
					Aliases: []string{"4.7.0"},
					Description: "This task does a `CONCURRENT` create of the `idx_manifest_index_manifest_id` index in the `indexer` database.\n" +
						"This may take a long time if the indexer database has gotten large.\n\n" +
						"The command will attempt to resume work if it is interrupted.",
					Usage:  "create `idx_manifest_index_manifest_id` index in the `indexer` database",
					Action: adminPre470,
				},
				{
					Name:    "v4.7.3",
					Aliases: []string{"4.7.3"},
					Description: "This task does a `CONCURRENT` create of the `idx_manifest_layer_layer_id` index in the `indexer` database.\n" +
						"This may take a long time if the indexer database has gotten large.\n\n" +
						"The command will attempt to resume work if it is interrupted.",
					Usage:  "create `idx_manifest_layer_layer_id` index in the `indexer` database",
					Action: adminPre473,
				},
			},
			Before: otherVersion,
		},
		{
			Name:        "post",
			Description: "Tasks that can be run after a Clair version is deployed",
			Usage:       "run post-upgrade task",
			ArgsUsage:   "\b",
			Subcommands: []*cli.Command{
				{
					Name:    "v4.7.0",
					Aliases: []string{"4.7.0"},
					Description: "This task deletes all the pyupio data from the matcher DB's vuln table.\n" +
						"The new python matcher can't handle pyuoio data and can cause errors.\n\n",
					Usage:  "delete pyupio vulns in from the matcher DB",
					Action: adminPost470,
				},
			},
			Before: otherVersion,
		},
		{
			Name:        "oneoff",
			Description: "Tasks that may be useful on occasion",
			Usage:       "run one-off task",
			ArgsUsage:   "\b",
			Subcommands: []*cli.Command{
				{
					Name: "update-golang-packages",
					Description: "This task will update the golang packages in the `package` table with the `norm_versions` and `norm_kind`.\n" +
						"Relevant package names are gleaned from the vulnerabilities in the matchers `vuln` table.\n\n",
					Usage:  "update golang packages in the indexer DB",
					Action: updateGoPackages,
				},
			},
		},
	},
}

// If the argument that would be interpreted as a subcommand is just a version
// we don't know about, exit 0.
func otherVersion(c *cli.Context) error {
	args := c.Args()
	if args.Len() != 1 {
		return nil
	}
	n := args.First()
	for _, cmd := range c.Command.VisibleCommands() {
		if cmd.HasName(n) {
			return nil
		}
	}
	if verRegexp.MatchString(n) {
		os.Exit(0)
	}
	return nil
}

// This is the semver regexp.
var verRegexp = regexp.MustCompile(`^v?(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

// Attempt to build the giant index that the migrations in 4.7.0 check for.
func adminPre470(c *cli.Context) error {
	ctx := c.Context
	fi, err := os.Stat(c.Path("config"))
	switch {
	case !errors.Is(err, nil):
		return fmt.Errorf("bad config: %w", err)
	case fi.IsDir():
		return fmt.Errorf("bad config: is a directory")
	}
	cfg, err := loadConfig(c.Path("config"))
	if err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}
	dsn := cfg.Indexer.ConnString

	pgcfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("error parsing dsn: %w", err)
	}
	zlog.Info(ctx).
		Str("host", pgcfg.ConnConfig.Host).
		Str("database", pgcfg.ConnConfig.Database).
		Str("user", pgcfg.ConnConfig.User).
		Uint16("port", pgcfg.ConnConfig.Port).
		Msg("using discovered connection params")

	zlog.Debug(ctx).
		Msg("resizing pool to 2 connections")
	pgcfg.MaxConns = 2
	pool, err := pgxpool.ConnectConfig(ctx, pgcfg)
	if err != nil {
		return fmt.Errorf("error creating pool: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("error connecting to database: %w", err)
	}

	return pool.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
		const checkindex = `SELECT pg_index.indisvalid FROM pg_class, pg_index WHERE pg_index.indexrelid = pg_class.oid AND pg_class.relname = 'idx_manifest_index_manifest_id';`
		const mkindex = `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_manifest_index_manifest_id ON manifest_index(manifest_id);`
		const reindex = `REINDEX INDEX CONCURRENTLY idx_manifest_index_manifest_id;`
		var ok *bool
		if err := conn.QueryRow(ctx, checkindex).Scan(&ok); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				zlog.Info(ctx).
					AnErr("index_check", err).
					Msg("error checking index existence")
			}
		}
		var query = mkindex
		if ok != nil && !*ok { // If it exists but isn't valid:
			query = reindex
		}
		if _, err := conn.Exec(ctx, query); err != nil {
			return fmt.Errorf("error (re)indexing database: %w", err)
		}
		zlog.Info(ctx).Msg("pre v4.7.0 admin done")
		return nil
	})
}

// Delete pyupio vulns from the DB.
func adminPost470(c *cli.Context) error {
	ctx := c.Context
	fi, err := os.Stat(c.Path("config"))
	switch {
	case !errors.Is(err, nil):
		return fmt.Errorf("bad config: %w", err)
	case fi.IsDir():
		return fmt.Errorf("bad config: is a directory")
	}
	cfg, err := loadConfig(c.Path("config"))
	if err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}
	dsn := cfg.Matcher.ConnString

	pgcfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("error parsing dsn: %w", err)
	}
	zlog.Info(ctx).
		Str("host", pgcfg.ConnConfig.Host).
		Str("database", pgcfg.ConnConfig.Database).
		Str("user", pgcfg.ConnConfig.User).
		Uint16("port", pgcfg.ConnConfig.Port).
		Msg("using discovered connection params")

	zlog.Debug(ctx).
		Msg("resizing pool to 2 connections")
	pgcfg.MaxConns = 2
	pool, err := pgxpool.ConnectConfig(ctx, pgcfg)
	if err != nil {
		return fmt.Errorf("error creating pool: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("error connecting to database: %w", err)
	}

	return pool.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
		const deleteUpdateOperations = `DELETE FROM update_operation WHERE updater = 'pyupio';`
		const deleteVulns = `
		DELETE FROM vuln v1 USING
			vuln v2
			LEFT JOIN uo_vuln uvl
				ON v2.id = uvl.vuln
			WHERE uvl.vuln IS NULL
			AND v2.updater = 'pyupio'
		AND v1.id = v2.id;
		`
		if _, err := conn.Exec(ctx, deleteUpdateOperations); err != nil {
			return fmt.Errorf("error deleting update operations: %w", err)
		}
		if _, err := conn.Exec(ctx, deleteVulns); err != nil {
			return fmt.Errorf("error deleting vulns: %w", err)
		}

		zlog.Info(ctx).Msg("post v4.7.0 admin done")
		return nil
	})
}

// Attempt to build the index that the migrations in 4.7.3 check for.
func adminPre473(c *cli.Context) error {
	ctx := c.Context
	fi, err := os.Stat(c.Path("config"))
	switch {
	case !errors.Is(err, nil):
		return fmt.Errorf("bad config: %w", err)
	case fi.IsDir():
		return fmt.Errorf("bad config: is a directory")
	}
	cfg, err := loadConfig(c.Path("config"))
	if err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}
	dsn := cfg.Indexer.ConnString

	pgcfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("error parsing dsn: %w", err)
	}
	zlog.Info(ctx).
		Str("host", pgcfg.ConnConfig.Host).
		Str("database", pgcfg.ConnConfig.Database).
		Str("user", pgcfg.ConnConfig.User).
		Uint16("port", pgcfg.ConnConfig.Port).
		Msg("using discovered connection params")

	zlog.Debug(ctx).
		Msg("resizing pool to 2 connections")
	pgcfg.MaxConns = 2
	pool, err := pgxpool.ConnectConfig(ctx, pgcfg)
	if err != nil {
		return fmt.Errorf("error creating pool: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("error connecting to database: %w", err)
	}

	return pool.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
		const checkindex = `SELECT pg_index.indisvalid FROM pg_class, pg_index WHERE pg_index.indexrelid = pg_class.oid AND pg_class.relname = 'idx_manifest_layer_layer_id';`
		const mkindex = `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_manifest_layer_layer_id ON manifest_layer (layer_id);`
		const reindex = `REINDEX INDEX CONCURRENTLY idx_manifest_layer_layer_id;`
		var ok *bool
		if err := conn.QueryRow(ctx, checkindex).Scan(&ok); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				zlog.Info(ctx).
					AnErr("index_check", err).
					Msg("error checking index existence")
			}
		}
		var query = mkindex
		if ok != nil && !*ok { // If it exists but isn't valid:
			query = reindex
		}
		if _, err := conn.Exec(ctx, query); err != nil {
			return fmt.Errorf("error (re)indexing database: %w", err)
		}
		zlog.Info(ctx).Msg("pre v4.7.3 admin done")
		return nil
	})
}

func updateGoPackages(c *cli.Context) error {
	const (
		// TODO (crozzy): This could describe something more interesting like >6 or 6-10 but
		// at the moment that seems like overkill.
		compatibleMigrationVersion = 7
		getPackageNames            = "SELECT DISTINCT package_name FROM vuln WHERE updater = 'osv/go'"
		getPackages                = "SELECT id, version FROM package WHERE name = $1 and norm_version IS NULL"
		updatePackages             = "UPDATE package SET norm_version=$1::int[], norm_kind=$2 WHERE id = $3 and norm_version IS NULL"
	)

	ctx := c.Context
	fi, err := os.Stat(c.Path("config"))
	switch {
	case !errors.Is(err, nil):
		return fmt.Errorf("bad config: %w", err)
	case fi.IsDir():
		return fmt.Errorf("bad config: is a directory")
	}
	cfg, err := loadConfig(c.Path("config"))
	if err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}
	matcherPool, err := createConnPool(ctx, cfg.Matcher.ConnString, 2)
	if err != nil {
		return fmt.Errorf("error creating indexer pool: %w", err)
	}
	defer matcherPool.Close()
	packageNames := []string{}
	err = matcherPool.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
		rows, err := conn.Query(ctx, getPackageNames)
		if err != nil {
			return fmt.Errorf("error getting package_name list: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var p string
			err := rows.Scan(&p)
			if err != nil {
				return err
			}
			packageNames = append(packageNames, p)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("could not get package names from matcher DB %w", err)
	}
	indexerPool, err := createConnPool(ctx, cfg.Indexer.ConnString, 2)
	if err != nil {
		return fmt.Errorf("error creating indexer pool: %w", err)
	}
	defer indexerPool.Close()
	err = checkMigrationVersion(ctx, indexerPool, "libindex_migrations", []int{compatibleMigrationVersion})
	if err != nil {
		return fmt.Errorf("error checking migration version: %w", err)
	}

	for _, p := range packageNames {
		err := indexerPool.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
			rows, err := conn.Query(ctx, getPackages, p)
			if err != nil {
				return fmt.Errorf("could not get packages for %s: %w", p, err)
			}
			defer rows.Close()
			for rows.Next() {
				var (
					id      int64
					version string
				)
				err := rows.Scan(&id, &version)
				if err != nil {
					return err
				}
				ctx = zlog.ContextWithValues(ctx, "package_name", p, "version", version)
				zlog.Debug(ctx).
					Msg("working on version")

				var nv claircore.Version
				ver, err := semver.NewVersion(version)
				switch {
				case errors.Is(err, nil):
					nv = fromSemver(ver)
				default:
					zlog.Warn(ctx).
						Err(err).
						Msg("error parsing semver")
					continue
				}
				var (
					vKind *string
					vNorm []int32
				)
				if nv.Kind != "" {
					vKind = &nv.Kind
					vNorm = nv.V[:]
				}

				tag, err := indexerPool.Exec(ctx, updatePackages, vNorm, vKind, id)
				if err != nil {
					return fmt.Errorf("error updating packages: %w", err)
				}
				zlog.Info(ctx).
					Int64("package_id", id).
					Int64("rows affected", tag.RowsAffected()).
					Msg("successfully updated package row")
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("error acquiring pool conn: %w", err)
		}
	}
	return nil
}

type ErrNonCompatibleMigrationVersion struct {
	version            int
	acceptableVersions []int
}

func NewErrNonCompatibleMigrationVersion(version int, acceptableVersions []int) ErrNonCompatibleMigrationVersion {
	return ErrNonCompatibleMigrationVersion{version: version, acceptableVersions: acceptableVersions}
}

func (e ErrNonCompatibleMigrationVersion) Error() string {
	return fmt.Sprintf("non-compatible migration version %d (acceptable versions: %v)", e.version, e.acceptableVersions)
}

func checkMigrationVersion(ctx context.Context, pool *pgxpool.Pool, migrationTable string, acceptableVersions []int) error {
	checkMigrationVersionQuery := fmt.Sprintf("SELECT MAX(version) FROM %s", migrationTable)
	return pool.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
		var version int
		err := conn.QueryRow(ctx, checkMigrationVersionQuery).Scan(&version)
		if err != nil {
			return err
		}
		for _, v := range acceptableVersions {
			if v == version {
				return nil
			}
		}
		return NewErrNonCompatibleMigrationVersion(version, acceptableVersions)
	})
}

func createConnPool(ctx context.Context, dsn string, maxConns int32) (*pgxpool.Pool, error) {
	pgcfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("error parsing dsn: %w", err)
	}
	zlog.Info(ctx).
		Str("host", pgcfg.ConnConfig.Host).
		Str("database", pgcfg.ConnConfig.Database).
		Str("user", pgcfg.ConnConfig.User).
		Uint16("port", pgcfg.ConnConfig.Port).
		Msg("using discovered connection params")

	zlog.Debug(ctx).
		Int32("pool size", maxConns).
		Msg("resizing pool")
	pgcfg.MaxConns = int32(maxConns)
	pool, err := pgxpool.ConnectConfig(ctx, pgcfg)
	if err != nil {
		return nil, fmt.Errorf("error creating pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("error connecting to database: %w", err)
	}
	return pool, nil
}

// FromSemVer is copied from the gobin package. It converts
// a semver.Version to a claircore.Version.
func fromSemver(v *semver.Version) (out claircore.Version) {
	out.Kind = `semver`
	// Leave a leading epoch, for good measure.
	out.V[1] = int32(v.Major())
	out.V[2] = int32(v.Minor())
	out.V[3] = int32(v.Patch())
	return out
}
