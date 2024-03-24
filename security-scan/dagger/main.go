// module for security scans like trivy, grype, etc.

package main

import (
	"context"
	"strconv"
)

type SecurityScan struct{}

// Scans filesystem with Trivy
func (m *SecurityScan) TrivyFileSystem(ctx context.Context,
	// Directory to scan
	dir *Directory,
	// +optional
	// +default="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
	severity string,
	// +optional
	exitCode int,
	// +optional
	// +default="table"
	format string,
) (string, error) {
	return dag.Container().From("aquasec/trivy:latest").WithDirectory("/toScan", dir).
		WithWorkdir("/toScan").
		WithExec([]string{
			"fs",
			"--severity", severity,
			"--exit-code", strconv.Itoa(exitCode),
			"--format", format,
			"."}).Stdout(ctx)
}
