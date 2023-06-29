package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
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
			},
			Before: otherVersion,
		},
		{
			Name:        "post",
			Description: "Tasks that can be run after a Clair version is deployed",
			Usage:       "run post-upgrade task",
			ArgsUsage:   "\b",
			Before:      otherVersion,
		},
		{
			Name:        "oneoff",
			Description: "Tasks that may be useful on occasion",
			Usage:       "run one-off task",
			ArgsUsage:   "\b",
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
		if err := conn.QueryRow(ctx, checkindex).Scan(ok); err != nil {
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
		return nil
	})
}
