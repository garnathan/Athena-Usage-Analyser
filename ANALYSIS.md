# Analyzing Exported Data

Once you have collected exports from the customer, use the `analyse_exports.py` script to generate comprehensive reports.

## Prerequisites

The script automatically installs required dependencies (matplotlib) on first run. No manual installation needed.

## Basic Usage

```bash
# Analyze all exports in a folder (generates HTML, auto-opens in browser)
python3 analyse_exports.py /path/to/exports/

# Analyze a single zip file
python3 analyse_exports.py /path/to/athena-usage-20240127-120000.zip

# Generate HTML but don't auto-open
python3 analyse_exports.py ./exports/ --no-open
```

## Output Options

```bash
# Generate text report instead of HTML
python3 analyse_exports.py ./exports/ --output report.txt

# Generate HTML report at custom path
python3 analyse_exports.py ./exports/ --html custom-report.html

# Save graphs as separate image files
python3 analyse_exports.py ./exports/ --graphs ./graphs/

# Text report with separate graph files
python3 analyse_exports.py ./exports/ --output report.txt --graphs ./graphs/
```

## What the Analysis Provides

**Basic Usage Metrics:**
- Overview statistics (total queries, data scanned, unique users)
- Query types distribution (SELECT, INSERT, CTAS, etc.)
- Workgroup analysis (queries, users, data scanned per workgroup)
- Top users by query count
- Database and table usage
- Most frequent query patterns (all patterns sorted by frequency)
- S3 bucket access patterns
- Daily activity summary

**Migration Readiness Analysis:**
- **Migration Readiness Score**: 0-100 overall score with LOW/MEDIUM/HIGH rating
- **Query Complexity Analysis**:
  - High complexity queries (3+ JOINs)
  - JOIN type breakdown (LEFT, RIGHT, INNER, OUTER, CROSS)
  - CTE (WITH clause) usage
  - Potential full table scans
- **DDL Operations Tracking**:
  - CREATE, DROP, ALTER, TRUNCATE counts
  - DDL by user and time of day
  - Tables with frequent DDL activity
- **Long-Running Query Detection**:
  - Queries 10-30 minutes
  - Queries 30+ minutes
  - Queries exceeding 1 hour
- **Concurrency & Performance**:
  - Peak concurrent queries per minute
  - Partition filter usage analysis
- **SQL Compatibility Flags**:
  - Features requiring attention during migration
  - CTAS operations, ACID tables, geospatial functions, etc.

**Graphs:**
- Query types distribution (horizontal bar chart)
- Daily activity bar chart
- Workgroup queries comparison
- Data scanned by workgroup
- Top users visualization
- S3 bucket operations breakdown
- Query pattern frequency

**HTML Report:**
- Self-contained HTML file with embedded graphs
- Color-coded readiness indicators
- Easy to share with stakeholders

## Example Workflow

1. Deploy the CloudFormation stack to customer account
2. Let it run for desired period (days/weeks)
3. Download exports from S3:
   ```bash
   aws s3 sync s3://athena-usage-analyser-analysis-<ACCOUNT_ID>/exports/ ./customer-exports/
   ```
4. Run analysis:
   ```bash
   python3 analyse_exports.py ./customer-exports/ --html customer-report.html
   ```
5. Open `customer-report.html` in browser to review findings
