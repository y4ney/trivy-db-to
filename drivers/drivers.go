package drivers

import "context"

type Driver interface {
	Migrate(ctx context.Context) error

	InsertVuln(ctx context.Context, vulns [][][]byte) error
	InsertVulnAdvisory(ctx context.Context, secAdvisories [][][]byte) error

	InsertDataSource(ctx context.Context, dataSources [][][]byte) error
	TruncateVulns(ctx context.Context) error
	TruncateVulnAdvisories(ctx context.Context) error
	TruncateDataSource(ctx context.Context) error
}
