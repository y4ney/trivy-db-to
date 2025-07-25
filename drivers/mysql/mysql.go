package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type Mysql struct {
	db                       *sql.DB
	vulnerabilitiesTableName string
	advisoryTableName        string
	dataSourceTableName      string
}

// New return *Mysql
func New(db *sql.DB, vulnerabilitiesTableName, advisoryTableName string, dataSourceTableName string) (*Mysql, error) {
	return &Mysql{
		db:                       db,
		vulnerabilitiesTableName: vulnerabilitiesTableName,
		advisoryTableName:        advisoryTableName,
		dataSourceTableName:      dataSourceTableName,
	}, nil
}

func (m *Mysql) Migrate(ctx context.Context) error {
	var count int
	stmt := fmt.Sprintf("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = database() AND table_name IN ('%s', '%s','%s');", m.vulnerabilitiesTableName, m.advisoryTableName, m.dataSourceTableName) //nolint:gosec
	if err := m.db.QueryRowContext(ctx, stmt).Scan(&count); err != nil {
		return err
	}
	switch count {
	case 3:
		// migrate from v1
		stmt = fmt.Sprintf(`ALTER TABLE %s MODIFY vulnerability_id varchar (128) NOT NULL;`, m.vulnerabilitiesTableName)
		if _, err := m.db.Exec(stmt); err != nil {
			return err
		}
		stmt = fmt.Sprintf(`ALTER TABLE %s MODIFY vulnerability_id varchar (128) NOT NULL;`, m.advisoryTableName)
		if _, err := m.db.Exec(stmt); err != nil {
			return err
		}
		stmt = fmt.Sprintf(`ALTER TABLE %s MODIFY source_key varchar (128) NOT NULL;`, m.dataSourceTableName)
		if _, err := m.db.Exec(stmt); err != nil {
			return err
		}
		return nil
	case 1:
		return errors.New("invalid table schema")
	}

	stmt = fmt.Sprintf(`CREATE TABLE %s (
id int PRIMARY KEY AUTO_INCREMENT,
vulnerability_id varchar (128) NOT NULL,
value json NOT NULL,
created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
) COMMENT = 'vulnerabilities obtained via Trivy DB' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`, m.vulnerabilitiesTableName)

	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE INDEX v_vulnerability_id_idx ON %s(vulnerability_id) USING BTREE;`, m.vulnerabilitiesTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE TABLE %s (
id int PRIMARY KEY AUTO_INCREMENT,
vulnerability_id varchar (128) NOT NULL,
platform varchar (50) NOT NULL,
segment varchar (50) NOT NULL,
package varchar (100) NOT NULL,
value json NOT NULL,
created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
) COMMENT = 'vulnerability advisories obtained via Trivy DB' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`, m.advisoryTableName)

	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE INDEX va_vulnerability_advisories_idx ON %s(vulnerability_id, platform, segment, package) USING BTREE;`, m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE INDEX va_vulnerability_id_idx ON %s(vulnerability_id) USING BTREE;`, m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE INDEX va_platform_idx ON %s(platform) USING BTREE;`, m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE INDEX va_source_idx ON %s(platform, segment) USING BTREE;`, m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE INDEX va_source_package_idx ON %s(platform, segment, package) USING BTREE;`, m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	// 创建 data_source 表
	stmt = fmt.Sprintf(`CREATE TABLE %s (
id int PRIMARY KEY AUTO_INCREMENT,
source_key varchar (128) NOT NULL,
source_id varchar (128) NOT NULL,
source_name varchar (128) NOT NULL,
source_url varchar (128) NOT NULL,
created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
) COMMENT = 'data sources via Trivy DB' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`, m.dataSourceTableName)

	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE INDEX v_key_idx ON %s(source_key) USING BTREE;`, m.dataSourceTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	return nil
}

func (m *Mysql) InsertVuln(ctx context.Context, vulns [][][]byte) error {
	query := fmt.Sprintf("INSERT INTO %s(vulnerability_id,value) VALUES (?,?)%s", m.vulnerabilitiesTableName,
		strings.Repeat(", (?,?)", len(vulns)-1)) //nolint:gosec

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

func (m *Mysql) InsertVulnAdvisory(ctx context.Context, secAdvisories [][][]byte) error {
	query := fmt.Sprintf("INSERT INTO %s(vulnerability_id,platform,segment,package,value) VALUES (?,?,?,?,?)%s", m.advisoryTableName, strings.Repeat(", (?,?,?,?,?)", len(secAdvisories)-1)) //nolint:gosec
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

func (m *Mysql) InsertDataSource(ctx context.Context, dataSources [][][]byte) error {
	// 定义一个结构体用于反序列化 JSON
	type Item struct {
		ID   string `json:"ID"`
		Name string `json:"Name"`
		URL  string `json:"URL"`
	}

	query := fmt.Sprintf("INSERT INTO %s(source_key,source_id,source_name,source_url) VALUES (?,?,?,?)%s", m.dataSourceTableName,
		strings.Repeat(", (?,?,?,?)", len(dataSources)-1)) //nolint:gosec

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

func (m *Mysql) TruncateVulns(ctx context.Context) error {
	stmt := fmt.Sprintf("TRUNCATE TABLE %s;", m.vulnerabilitiesTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}
	return nil
}

func (m *Mysql) TruncateVulnAdvisories(ctx context.Context) error {
	stmt := fmt.Sprintf("TRUNCATE TABLE %s;", m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}
	return nil
}

// TruncateDataSource 清空数据源表的数据（使用 TRUNCATE 语句）。
func (m *Mysql) TruncateDataSource(ctx context.Context) error {
	stmt := fmt.Sprintf("TRUNCATE TABLE %s;", m.dataSourceTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}
	return nil
}
