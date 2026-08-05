package models

import "time"

// ReportFormat represents a supported output format.
type ReportFormat string

const (
	ReportFormatHTML     ReportFormat = "html"
	ReportFormatJSON     ReportFormat = "json"
	ReportFormatMarkdown ReportFormat = "markdown"
	ReportFormatCSV      ReportFormat = "csv"
	ReportFormatSARIF    ReportFormat = "sarif"
)

// Report represents a complete analysis report over one or more targets.
type Report struct {
	Title       string
	Version     string
	GeneratedAt time.Time
	Results     []ScanResult
	Summary     ReportSummary
}

// ReportSummary holds aggregate statistics across all results.
type ReportSummary struct {
	TotalTargets  int
	TotalFindings int
	BySeverity    map[Severity]int
	RiskScore     float64
}
