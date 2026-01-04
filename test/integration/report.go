package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ModeTestReport holds test results for a single mode
type ModeTestReport struct {
	ModeName    string                 `json:"modeName"`
	ModeType    string                 `json:"modeType"`
	Error       string                 `json:"error,omitempty"`
	Consistency *ConsistencyTestResult `json:"consistency,omitempty"`
	Latency     *LatencyTestResult     `json:"latency,omitempty"`
	Throughput  *ThroughputTestResult  `json:"throughput,omitempty"`
	Stress      *StressTestResult      `json:"stress,omitempty"`
}

// FullTestReport holds complete test results
type FullTestReport struct {
	StartTime time.Time                  `json:"startTime"`
	EndTime   time.Time                  `json:"endTime"`
	Duration  time.Duration              `json:"duration"`
	Modes     map[string]*ModeTestReport `json:"modes"`
}

// Summary represents the test summary
type Summary struct {
	TotalModes       int     `json:"totalModes"`
	SuccessfulModes  int     `json:"successfulModes"`
	FailedModes      int     `json:"failedModes"`
	OverallSuccess   bool    `json:"overallSuccess"`
	ConsistencyRate  float64 `json:"consistencyRate"`
	AvgLatencyMs     float64 `json:"avgLatencyMs"`
	TotalThroughput  float64 `json:"totalThroughputMBps"`
	TotalConnections int     `json:"totalConnections"`
}

// GetSummary generates a summary from the report
func (r *FullTestReport) GetSummary() *Summary {
	s := &Summary{
		TotalModes: len(r.Modes),
	}

	var totalMessages, successMessages int
	var latencySum float64
	var latencyCount int
	var throughputSum float64

	for _, mode := range r.Modes {
		if mode.Error != "" {
			s.FailedModes++
			continue
		}
		s.SuccessfulModes++

		if mode.Consistency != nil {
			totalMessages += mode.Consistency.TotalMessages
			successMessages += mode.Consistency.SuccessMessages
		}

		if mode.Latency != nil && mode.Latency.SampleCount > 0 {
			latencySum += float64(mode.Latency.AvgLatency.Milliseconds())
			latencyCount++
		}

		if mode.Throughput != nil {
			throughputSum += mode.Throughput.SendRate
		}

		if mode.Stress != nil {
			s.TotalConnections += mode.Stress.SuccessConns
		}
	}

	if totalMessages > 0 {
		s.ConsistencyRate = float64(successMessages) / float64(totalMessages) * 100
	}

	if latencyCount > 0 {
		s.AvgLatencyMs = latencySum / float64(latencyCount)
	}

	s.TotalThroughput = throughputSum
	s.OverallSuccess = s.FailedModes == 0 && s.ConsistencyRate >= 99.0

	return s
}

// PrintReport prints the test report to stdout
func (r *FullTestReport) PrintReport() {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("                    NatSvr Integration Test Report")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Start Time:  %s\n", r.StartTime.Format(time.RFC3339))
	fmt.Printf("End Time:    %s\n", r.EndTime.Format(time.RFC3339))
	fmt.Printf("Duration:    %s\n", r.Duration)
	fmt.Println(strings.Repeat("-", 80))

	for _, mode := range r.Modes {
		fmt.Printf("\n[%s] Type: %s\n", mode.ModeName, mode.ModeType)
		fmt.Println(strings.Repeat("-", 40))

		if mode.Error != "" {
			fmt.Printf("  ERROR: %s\n", mode.Error)
			continue
		}

		// Consistency Results
		if mode.Consistency != nil {
			c := mode.Consistency
			successRate := float64(0)
			if c.TotalMessages > 0 {
				successRate = float64(c.SuccessMessages) / float64(c.TotalMessages) * 100
			}
			fmt.Println("  Consistency Test:")
			fmt.Printf("    Total Messages:    %d\n", c.TotalMessages)
			fmt.Printf("    Success:           %d (%.2f%%)\n", c.SuccessMessages, successRate)
			fmt.Printf("    Checksum Errors:   %d\n", c.ChecksumErrors)
			fmt.Printf("    Data Mismatch:     %d\n", c.DataMismatch)
			fmt.Printf("    Sequence Mismatch: %d\n", c.SequenceMismatch)
			if len(c.Errors) > 0 {
				fmt.Printf("    Errors:            %d\n", len(c.Errors))
			}
		}

		// Latency Results
		if mode.Latency != nil && mode.Latency.SampleCount > 0 {
			l := mode.Latency
			fmt.Println("  Latency Test:")
			fmt.Printf("    Samples:   %d\n", l.SampleCount)
			fmt.Printf("    Min:       %v\n", l.MinLatency)
			fmt.Printf("    Max:       %v\n", l.MaxLatency)
			fmt.Printf("    Avg:       %v\n", l.AvgLatency)
			fmt.Printf("    P50:       %v\n", l.P50Latency)
			fmt.Printf("    P95:       %v\n", l.P95Latency)
			fmt.Printf("    P99:       %v\n", l.P99Latency)
		}

		// Throughput Results
		if mode.Throughput != nil && mode.Throughput.Duration > 0 {
			t := mode.Throughput
			fmt.Println("  Throughput Test:")
			fmt.Printf("    Duration:      %v\n", t.Duration)
			fmt.Printf("    Messages Sent: %d\n", t.MessagesSent)
			fmt.Printf("    Bytes Sent:    %s\n", formatBytes(t.BytesSent))
			fmt.Printf("    Send Rate:     %.2f MB/s\n", t.SendRate)
			fmt.Printf("    Recv Rate:     %.2f MB/s\n", t.RecvRate)
		}

		// Stress Test Results
		if mode.Stress != nil {
			s := mode.Stress
			successRate := float64(0)
			if s.TotalMessages > 0 {
				successRate = float64(s.SuccessMessages) / float64(s.TotalMessages) * 100
			}
			fmt.Println("  Stress Test:")
			fmt.Printf("    Duration:     %v\n", s.Duration)
			fmt.Printf("    Connections:  %d success / %d failed\n", s.SuccessConns, s.FailedConns)
			fmt.Printf("    Messages:     %d total, %d success (%.2f%%)\n",
				s.TotalMessages, s.SuccessMessages, successRate)
			fmt.Printf("    Total Bytes:  %s\n", formatBytes(s.TotalBytes))
			fmt.Printf("    Throughput:   %.2f MB/s\n", s.Throughput)
		}
	}

	// Print Summary
	summary := r.GetSummary()
	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("                              Summary")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Total Modes:        %d\n", summary.TotalModes)
	fmt.Printf("Successful:         %d\n", summary.SuccessfulModes)
	fmt.Printf("Failed:             %d\n", summary.FailedModes)
	fmt.Printf("Consistency Rate:   %.2f%%\n", summary.ConsistencyRate)
	fmt.Printf("Avg Latency:        %.2f ms\n", summary.AvgLatencyMs)
	fmt.Printf("Total Throughput:   %.2f MB/s\n", summary.TotalThroughput)
	fmt.Printf("Total Connections:  %d\n", summary.TotalConnections)
	fmt.Println()

	if summary.OverallSuccess {
		fmt.Println("Status: ✓ ALL TESTS PASSED")
	} else {
		fmt.Println("Status: ✗ SOME TESTS FAILED")
	}
	fmt.Println(strings.Repeat("=", 80))
}

// SaveJSON saves the report as JSON
func (r *FullTestReport) SaveJSON(filename string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// PrintComparisonTable prints a comparison table of all modes
func (r *FullTestReport) PrintComparisonTable() {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("                             Mode Comparison Table")
	fmt.Println(strings.Repeat("=", 100))

	// Header
	fmt.Printf("%-20s %-12s %-12s %-15s %-15s %-15s\n",
		"Mode", "Type", "Consistency", "Avg Latency", "Throughput", "Stress")
	fmt.Println(strings.Repeat("-", 100))

	for name, mode := range r.Modes {
		if mode.Error != "" {
			fmt.Printf("%-20s %-12s ERROR: %s\n", name, mode.ModeType, mode.Error)
			continue
		}

		consistency := "-"
		if mode.Consistency != nil && mode.Consistency.TotalMessages > 0 {
			rate := float64(mode.Consistency.SuccessMessages) / float64(mode.Consistency.TotalMessages) * 100
			consistency = fmt.Sprintf("%.1f%%", rate)
		}

		latency := "-"
		if mode.Latency != nil && mode.Latency.SampleCount > 0 {
			latency = fmt.Sprintf("%.2f ms", float64(mode.Latency.AvgLatency.Microseconds())/1000)
		}

		throughput := "-"
		if mode.Throughput != nil {
			throughput = fmt.Sprintf("%.2f MB/s", mode.Throughput.SendRate)
		}

		stress := "-"
		if mode.Stress != nil && mode.Stress.TotalMessages > 0 {
			rate := float64(mode.Stress.SuccessMessages) / float64(mode.Stress.TotalMessages) * 100
			stress = fmt.Sprintf("%.1f%% (%d conn)", rate, mode.Stress.SuccessConns)
		}

		fmt.Printf("%-20s %-12s %-12s %-15s %-15s %-15s\n",
			name, mode.ModeType, consistency, latency, throughput, stress)
	}

	fmt.Println(strings.Repeat("=", 100))
}

// formatBytes formats bytes to human readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// GenerateMarkdownReport generates a markdown report
func (r *FullTestReport) GenerateMarkdownReport() string {
	var sb strings.Builder

	sb.WriteString("# NatSvr Integration Test Report\n\n")
	sb.WriteString(fmt.Sprintf("**Start Time:** %s  \n", r.StartTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**End Time:** %s  \n", r.EndTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n\n", r.Duration))

	// Summary Table
	sb.WriteString("## Summary\n\n")
	summary := r.GetSummary()

	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Total Modes | %d |\n", summary.TotalModes))
	sb.WriteString(fmt.Sprintf("| Successful | %d |\n", summary.SuccessfulModes))
	sb.WriteString(fmt.Sprintf("| Failed | %d |\n", summary.FailedModes))
	sb.WriteString(fmt.Sprintf("| Consistency Rate | %.2f%% |\n", summary.ConsistencyRate))
	sb.WriteString(fmt.Sprintf("| Avg Latency | %.2f ms |\n", summary.AvgLatencyMs))
	sb.WriteString(fmt.Sprintf("| Total Throughput | %.2f MB/s |\n", summary.TotalThroughput))
	sb.WriteString("\n")

	// Mode Comparison
	sb.WriteString("## Mode Comparison\n\n")
	sb.WriteString("| Mode | Type | Consistency | Latency (avg) | Throughput | Stress Success |\n")
	sb.WriteString("|------|------|-------------|---------------|------------|----------------|\n")

	for name, mode := range r.Modes {
		if mode.Error != "" {
			sb.WriteString(fmt.Sprintf("| %s | %s | ERROR | - | - | - |\n", name, mode.ModeType))
			continue
		}

		consistency := "-"
		if mode.Consistency != nil && mode.Consistency.TotalMessages > 0 {
			rate := float64(mode.Consistency.SuccessMessages) / float64(mode.Consistency.TotalMessages) * 100
			consistency = fmt.Sprintf("%.1f%%", rate)
		}

		latency := "-"
		if mode.Latency != nil && mode.Latency.SampleCount > 0 {
			latency = fmt.Sprintf("%.2f ms", float64(mode.Latency.AvgLatency.Microseconds())/1000)
		}

		throughput := "-"
		if mode.Throughput != nil {
			throughput = fmt.Sprintf("%.2f MB/s", mode.Throughput.SendRate)
		}

		stress := "-"
		if mode.Stress != nil && mode.Stress.TotalMessages > 0 {
			rate := float64(mode.Stress.SuccessMessages) / float64(mode.Stress.TotalMessages) * 100
			stress = fmt.Sprintf("%.1f%%", rate)
		}

		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
			name, mode.ModeType, consistency, latency, throughput, stress))
	}

	sb.WriteString("\n")

	// Detailed Results
	sb.WriteString("## Detailed Results\n\n")

	for name, mode := range r.Modes {
		sb.WriteString(fmt.Sprintf("### %s (%s)\n\n", name, mode.ModeType))

		if mode.Error != "" {
			sb.WriteString(fmt.Sprintf("**Error:** %s\n\n", mode.Error))
			continue
		}

		if mode.Consistency != nil {
			c := mode.Consistency
			sb.WriteString("#### Consistency Test\n\n")
			sb.WriteString(fmt.Sprintf("- Total Messages: %d\n", c.TotalMessages))
			sb.WriteString(fmt.Sprintf("- Success: %d\n", c.SuccessMessages))
			sb.WriteString(fmt.Sprintf("- Checksum Errors: %d\n", c.ChecksumErrors))
			sb.WriteString(fmt.Sprintf("- Data Mismatch: %d\n", c.DataMismatch))
			sb.WriteString("\n")
		}

		if mode.Latency != nil && mode.Latency.SampleCount > 0 {
			l := mode.Latency
			sb.WriteString("#### Latency Test\n\n")
			sb.WriteString(fmt.Sprintf("- Samples: %d\n", l.SampleCount))
			sb.WriteString(fmt.Sprintf("- Min: %v\n", l.MinLatency))
			sb.WriteString(fmt.Sprintf("- Max: %v\n", l.MaxLatency))
			sb.WriteString(fmt.Sprintf("- P50: %v\n", l.P50Latency))
			sb.WriteString(fmt.Sprintf("- P99: %v\n", l.P99Latency))
			sb.WriteString("\n")
		}

		if mode.Throughput != nil {
			t := mode.Throughput
			sb.WriteString("#### Throughput Test\n\n")
			sb.WriteString(fmt.Sprintf("- Duration: %v\n", t.Duration))
			sb.WriteString(fmt.Sprintf("- Send Rate: %.2f MB/s\n", t.SendRate))
			sb.WriteString(fmt.Sprintf("- Recv Rate: %.2f MB/s\n", t.RecvRate))
			sb.WriteString("\n")
		}

		if mode.Stress != nil {
			s := mode.Stress
			sb.WriteString("#### Stress Test\n\n")
			sb.WriteString(fmt.Sprintf("- Connections: %d/%d\n", s.SuccessConns, s.TotalConnections))
			sb.WriteString(fmt.Sprintf("- Messages: %d/%d\n", s.SuccessMessages, s.TotalMessages))
			sb.WriteString(fmt.Sprintf("- Throughput: %.2f MB/s\n", s.Throughput))
			sb.WriteString("\n")
		}
	}

	// Result
	sb.WriteString("## Result\n\n")
	if summary.OverallSuccess {
		sb.WriteString("**ALL TESTS PASSED**\n")
	} else {
		sb.WriteString("**SOME TESTS FAILED**\n")
	}

	return sb.String()
}

// SaveMarkdown saves the report as markdown
func (r *FullTestReport) SaveMarkdown(filename string) error {
	return os.WriteFile(filename, []byte(r.GenerateMarkdownReport()), 0644)
}

