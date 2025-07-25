package internal

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	db2 "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/k1LoW/trivy-db-to/drivers"
	"github.com/k1LoW/trivy-db-to/drivers/mysql"
	"github.com/k1LoW/trivy-db-to/drivers/postgres"
	"github.com/k1LoW/trivy-db-to/drivers/sqlite"
	"github.com/samber/lo"
	"github.com/xo/dburl"
	bolt "go.etcd.io/bbolt"
)

const (
	chunkSize        = 5000
	vulnBucket       = "vulnerability"
	dataSourceBucket = "data-source"
	appVersion       = "99.9.9"
	dbRepository     = "ghcr.io/aquasecurity/trivy-db"
)

func FetchTrivyDB(ctx context.Context, cacheDir string, light, quiet, skipUpdate bool) error {
	log.Logger.Info("Fetching and updating Trivy DB ... ")
	dbPath := db2.Path(cacheDir)
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		return err
	}

	client := db.NewClient(cacheDir, quiet, db.WithDBRepository(dbRepository))
	needsUpdate, err := client.NeedsUpdate(appVersion, skipUpdate)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	if needsUpdate {
		log.Logger.Infof("Need to update DB, and DB Repository is %s", dbRepository)
		log.Logger.Info("Downloading DB...")
		if err = client.Download(ctx, cacheDir, types.RemoteOptions{}); err != nil {
			return fmt.Errorf("failed to download vulnerability DB: %w", err)
		}
	}
	log.Logger.Info("done")

	return nil
}

func InitDB(ctx context.Context, dsn, vulnerabilityTableName, advisoryTableName string,
	dataSourceTableName string) error {
	var (
		driver drivers.Driver
		err    error
	)
	log.Logger.Info("Initializing vulnerability information tables ...")
	db, d, err := dbOpen(dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	switch d {
	case "mysql":
		driver, err = mysql.New(db, vulnerabilityTableName, advisoryTableName, dataSourceTableName)
		if err != nil {
			return err
		}
	case "postgres":
		driver, err = postgres.New(db, vulnerabilityTableName, advisoryTableName, dataSourceTableName)
		if err != nil {
			return err
		}
	case "sqlite":
		driver, err = sqlite.New(db, vulnerabilityTableName, advisoryTableName, dataSourceTableName)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported driver '%s'", d)
	}

	if err := driver.Migrate(ctx); err != nil {
		return err
	}
	log.Logger.Info("done")
	return nil
}

func UpdateDB(ctx context.Context, cacheDir, dsn, vulnerabilityTableName, advisoryTableName string,
	targetSources []string, dataSourceTableName string) error {
	log.Logger.Info("Updating vulnerability information tables ...")
	var (
		driver drivers.Driver
		err    error
	)

	db, d, err := dbOpen(dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	switch d {
	case "mysql":
		driver, err = mysql.New(db, vulnerabilityTableName, advisoryTableName, dataSourceTableName)
		if err != nil {
			return err
		}
	case "postgres":
		driver, err = postgres.New(db, vulnerabilityTableName, advisoryTableName, dataSourceTableName)
		if err != nil {
			return err
		}
	case "sqlite":
		driver, err = sqlite.New(db, vulnerabilityTableName, advisoryTableName, dataSourceTableName)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported driver '%s'", d)
	}

	trivyDb, err := bolt.Open(filepath.Join(cacheDir, "db", "trivy.db"), 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return err
	}
	defer trivyDb.Close()

	if err := trivyDb.View(func(tx *bolt.Tx) error {
		log.Logger.Infof("Updating table '%s' ...", vulnerabilityTableName)
		if err := driver.TruncateVulns(ctx); err != nil {
			return err
		}
		b := tx.Bucket([]byte(vulnBucket))
		c := b.Cursor()
		started := false
		ended := false
		for {
			var vulns [][][]byte
			if !started {
				k, v := c.First()
				vulns = append(vulns, [][]byte{k, v})
				started = true
			}
			for i := 0; i < chunkSize; i++ {
				k, v := c.Next()
				if k == nil {
					ended = true
					break
				}
				vulns = append(vulns, [][]byte{k, v})
			}
			if len(vulns) > 0 {
				if err := driver.InsertVuln(ctx, vulns); err != nil {
					return err
				}
			}
			if ended {
				break
			}
		}

		if err = updateDataSource(dataSourceBucket, driver, ctx, tx); err != nil {
			log.Logger.Fatalf("Failed to update data-source table:%s", err.Error())
		}

		var sourceRe []*regexp.Regexp
		for _, s := range targetSources {
			re, err := regexp.Compile(s)
			if err != nil {
				return err
			}
			sourceRe = append(sourceRe, re)
		}
		log.Logger.Infof("Updating table '%s' ...", advisoryTableName)
		if err := driver.TruncateVulnAdvisories(ctx); err != nil {
			return err
		}
		if err := tx.ForEach(func(source []byte, b *bolt.Bucket) error {
			var s = string(source)
			if s == vulnBucket {
				return nil
			}

			if len(sourceRe) > 0 {
				found := false
				for _, re := range sourceRe {
					if re.MatchString(s) {
						found = true
						break
					}
				}
				if !found {
					return nil
				}
			}
			log.Logger.Infof("Writing security advisory: %s ...", s)
			c := b.Cursor()
			var secAdv [][][]byte
			for pkg, _ := c.First(); pkg != nil; pkg, _ = c.Next() {
				cb := b.Bucket(pkg)
				if cb == nil {
					continue
				}
				cbc := cb.Cursor()
				for vID, v := cbc.First(); vID != nil; vID, v = cbc.Next() {
					platform, segment := parsePlatformAndSegment(s)
					secAdv = append(secAdv, [][]byte{vID, platform, segment, pkg, v})
				}
			}
			chunked := lo.Chunk(secAdv, chunkSize)
			for _, c := range chunked {
				if err := driver.InsertVulnAdvisory(ctx, c); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}
	log.Logger.Info("done")
	return nil
}

func dbOpen(dsn string) (*sql.DB, string, error) {
	u, err := dburl.Parse(dsn)
	if err != nil {
		return nil, "", err
	}
	if u.Driver == "sqlite3" {
		u.Driver = "sqlite"
	}
	db, err := sql.Open(u.Driver, u.DSN)
	if err != nil {
		return nil, "", err
	}
	return db, u.Driver, nil
}

var numRe = regexp.MustCompile(`\d+`)

func parsePlatformAndSegment(s string) ([]byte, []byte) {
	const alpineEdgeSegment = "edge"
	platform := []byte(s)
	segment := []byte("")
	splited := strings.Split(s, " ")
	if len(splited) > 1 {
		last := splited[len(splited)-1]
		if numRe.MatchString(last) || last == alpineEdgeSegment {
			platform = []byte(strings.Join(splited[0:len(splited)-1], " "))
			segment = []byte(last)
		}
	}
	return platform, segment
}
func updateDataSource(dataSourceTableName string, driver drivers.Driver, ctx context.Context, tx *bolt.Tx) error {
	log.Logger.Infof("Updating table '%s' ...", dataSourceTableName)
	if err := driver.TruncateDataSource(ctx); err != nil {
		return err
	}
	b := tx.Bucket([]byte(dataSourceBucket))
	c := b.Cursor()
	started := false
	ended := false
	for {
		var dataSource [][][]byte
		if !started {
			k, v := c.First()
			dataSource = append(dataSource, [][]byte{k, v})
			started = true
		}
		for i := 0; i < chunkSize; i++ {
			k, v := c.Next()
			if k == nil {
				ended = true
				break
			}
			dataSource = append(dataSource, [][]byte{k, v})
		}
		if len(dataSource) > 0 {
			if err := driver.InsertDataSource(ctx, dataSource); err != nil {
				return err
			}
		}
		if ended {
			break
		}
	}
	return nil
}
