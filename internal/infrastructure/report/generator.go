package report

import (
	"context"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
)

type ReportService interface {
	GetReportData(ctx context.Context, scanID uint) (*entity.ScanReportData, error)
}

type PDFGenerator struct {
	chromiumPath string
}

func NewPDFGenerator(chromiumPath string) *PDFGenerator {
	return &PDFGenerator{chromiumPath: chromiumPath}
}

type Generator struct {
	reportService ReportService
	pdfGen       *PDFGenerator
	outputDir    string
}

func NewGenerator(reportService ReportService, pdfGen *PDFGenerator, outputDir string) *Generator {
	return &Generator{
		reportService: reportService,
		pdfGen:       pdfGen,
		outputDir:    outputDir,
	}
}
