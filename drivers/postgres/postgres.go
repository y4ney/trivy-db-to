package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type Postgres struct {
	db                       *sql.DB
	vulnerabilitiesTableName string
	advisoryTableName        string
	dataSourceTableName      string
}

// New return *Postgres
func New(db *sql.DB, vulnerabilitiesTableName, advisoryTableName string, dataSourceTableName string) (*Postgres, error) {
	return &Postgres{
		db:                       db,
		vulnerabilitiesTableName: vulnerabilitiesTableName,
		advisoryTableName:        advisoryTableName,
		dataSourceTableName:      dataSourceTableName,
	}, nil
}

func (m *Postgres) Migrate(ctx context.Context) error {
	var count int
	stmt := fmt.Sprintf("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name IN ('%s', '%s','%s');", m.vulnerabilitiesTableName, m.advisoryTableName, m.dataSourceTableName) //nolint:gosec
	if err := m.db.QueryRowContext(ctx, stmt).Scan(&count); err != nil {
		return err
	}
	switch count {
	case 3:
		// migrate from v1
		stmt = fmt.Sprintf(`ALTER TABLE %s ALTER COLUMN vulnerability_id TYPE varchar (128) USING vulnerability_id::varchar;`, m.vulnerabilitiesTableName)
		if _, err := m.db.Exec(stmt); err != nil {
			return err
		}
		stmt = fmt.Sprintf(`ALTER TABLE %s ALTER COLUMN vulnerability_id TYPE varchar (128) USING vulnerability_id::varchar;`, m.advisoryTableName)
		if _, err := m.db.Exec(stmt); err != nil {
			return err
		}
		stmt = fmt.Sprintf(`ALTER TABLE %s ALTER COLUMN source_key TYPE varchar (128) USING source_key::varchar;`, m.dataSourceTableName)
		if _, err := m.db.Exec(stmt); err != nil {
			return err
		}
		return nil
	case 1:
		return errors.New("invalid table schema")
	}

	stmt = fmt.Sprintf(`CREATE TABLE %s (
id serial PRIMARY KEY,
vulnerability_id varchar (128) NOT NULL,
value json NOT NULL,
created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
)`, m.vulnerabilitiesTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("COMMENT ON TABLE %s IS 'vulnerability obtained via Trivy DB';", m.vulnerabilitiesTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX v_vulnerability_id_idx ON %s(vulnerability_id);", m.vulnerabilitiesTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE TABLE %s (
id serial PRIMARY KEY,
vulnerability_id varchar (128) NOT NULL,
platform varchar (50) NOT NULL,
segment varchar (50) NOT NULL,
package varchar (100) NOT NULL,
value json NOT NULL,
created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
)`, m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`COMMENT ON TABLE %s IS 'vulnerability advisories obtained via Trivy DB';`, m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX va_vulnerability_advisories_idx ON %s(vulnerability_id, platform, segment, package)", m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX va_vulnerability_id_idx ON %s(vulnerability_id)", m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX va_platform_idx ON %s(platform)", m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX va_source_idx ON %s(platform, segment)", m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX va_source_package_idx ON %s(platform, segment, package)", m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	// 创建 data_source 表
	stmt = fmt.Sprintf(`CREATE TABLE %s (
id serial PRIMARY KEY,
source_key varchar (128) NOT NULL,
source_id varchar (128) NOT NULL,
source_name varchar (128) NOT NULL,
source_url varchar (128) NOT NULL,
created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
)`, m.dataSourceTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("COMMENT ON TABLE %s IS 'Data Source obtained via Trivy DB';", m.dataSourceTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX v_source_key_idx ON %s(source_key);", m.dataSourceTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	return nil
}

func (m *Postgres) InsertVuln(ctx context.Context, vulns [][][]byte) error {
	var iv []string
	for i := 0; i < len(vulns); i++ {
		iv = append(iv, fmt.Sprintf("($%d, $%d)", i*2+1, i*2+2))
	}
	query := fmt.Sprintf("INSERT INTO %s(vulnerability_id,value) VALUES %s", m.vulnerabilitiesTableName, strings.Join(iv, ",")) //nolint:gosec

	ins, err := m.db.Prepare(query)
	if err != nil {
		return err
	}

	var values []interface{}
	for _, vuln := range vulns {
		values = append(values, vuln[0], vuln[1])
	}
	{
		_, err := ins.Exec(values...)
		return err
	}
}

func (m *Postgres) InsertVulnAdvisory(ctx context.Context, secAdvisories [][][]byte) error {
	var iv []string
	for i := 0; i < len(secAdvisories); i++ {
		iv = append(iv, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d)", i*5+1, i*5+2, i*5+3, i*5+4, i*5+5))
	}
	query := fmt.Sprintf("INSERT INTO %s(vulnerability_id,platform,segment,package,value) VALUES %s", m.advisoryTableName, strings.Join(iv, ",")) //nolint:gosec
	ins, err := m.db.Prepare(query)
	if err != nil {
		return err
	}

	var values []interface{}
	for _, secAdvisory := range secAdvisories {
		values = append(values, secAdvisory[0], secAdvisory[1], secAdvisory[2], secAdvisory[3], secAdvisory[4])
	}
	{
		_, err := ins.Exec(values...)
		return err
	}
}

func (m *Postgres) InsertDataSource(ctx context.Context, dataSources [][][]byte) error {
	// 定义一个结构体用于反序列化 JSON
	type Item struct {
		ID   string `json:"ID"`
		Name string `json:"Name"`
		URL  string `json:"URL"`
	}

	var iv []string
	for i := 0; i < len(dataSources); i++ {
		iv = append(iv, fmt.Sprintf("($%d, $%d, $%d, $%d)", i*4+1, i*4+2, i*4+3, i*4+4))
	}
	query := fmt.Sprintf("INSERT INTO %s(source_key,source_id,source_name,source_url) VALUES %s", m.dataSourceTableName, strings.Join(iv, ",")) //nolint:gosec

	ins, err := m.db.Prepare(query)
	if err != nil {
		return err
	}

	var values []interface{}
	for _, dataSource := range dataSources {
		// 反序列化 JSON 到结构体
		var item Item
		if err = json.Unmarshal(dataSource[1], &item); err != nil {
			return err
		}
		values = append(values, dataSource[0], item.ID, item.Name, item.URL)
	}
	{
		_, err = ins.Exec(values...)
		return err
	}
}

func (m *Postgres) TruncateVulns(ctx context.Context) error {
	stmt := fmt.Sprintf("TRUNCATE TABLE %s", m.vulnerabilitiesTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}
	return nil
}

func (m *Postgres) TruncateVulnAdvisories(ctx context.Context) error {
	stmt := fmt.Sprintf("TRUNCATE TABLE %s", m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}
	return nil
}

// TruncateDataSource 清空数据源表的数据（使用 TRUNCATE 语句）。
func (m *Postgres) TruncateDataSource(ctx context.Context) error {
	stmt := fmt.Sprintf("TRUNCATE TABLE %s;", m.dataSourceTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}
	return nil
}
