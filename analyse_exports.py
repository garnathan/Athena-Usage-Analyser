#!/usr/bin/env python3
"""
Athena Usage Analysis Script

Analyzes exported zip files from the Athena Usage Analyser Lambda to produce
meaningful insights and visualizations about customer Athena and S3 usage.

By default, generates an HTML report and opens it in the browser.

Usage:
    python3 analyse_exports.py /path/to/exports/folder              # HTML report, auto-opens
    python3 analyse_exports.py /path/to/exports/folder --no-open    # HTML report, no auto-open
    python3 analyse_exports.py /path/to/exports/folder --output report.txt  # Text report instead
"""

import argparse
import json
import os
import sys
import zipfile
import subprocess
import webbrowser
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import io

# Required packages for full functionality
REQUIRED_PACKAGES = ["matplotlib"]


def install_dependencies():
    """Install required packages if not already installed."""
    for package in REQUIRED_PACKAGES:
        try:
            __import__(package)
        except ImportError:
            print(f"Installing required package: {package}...")
            try:
                subprocess.check_call(
                    ["pip3", "install", "--user", package],
                    stdout=subprocess.DEVNULL,
                )
                print(f"  {package} installed successfully.")
            except subprocess.CalledProcessError:
                # Try with --break-system-packages as fallback
                try:
                    subprocess.check_call(
                        ["pip3", "install", "--break-system-packages", package],
                        stdout=subprocess.DEVNULL,
                    )
                    print(f"  {package} installed successfully.")
                except subprocess.CalledProcessError as e:
                    print(f"  Failed to install {package}: {e}")
                    print(f"  Please run: pip3 install {package}")
                    sys.exit(1)


# Install dependencies before importing them
install_dependencies()

import matplotlib

matplotlib.use("Agg")  # Use non-interactive backend
import matplotlib.pyplot as plt

HAS_MATPLOTLIB = True


class AthenaExportAnalyser:
    """Analyzes exported Athena usage data from zip files."""

    def __init__(self, exports_path: str):
        self.exports_path = Path(exports_path)
        self.all_summaries: List[Dict] = []
        self.all_athena_events: List[Dict] = []
        self.all_s3_events: List[Dict] = []

        # Aggregated statistics
        self.workgroup_stats: Dict[str, Dict] = defaultdict(
            lambda: {
                "query_count": 0,
                "users": set(),
                "total_data_scanned": 0,
                "query_types": defaultdict(int),
            }
        )
        self.user_stats: Dict[str, Dict] = defaultdict(
            lambda: {
                "query_count": 0,
                "workgroups": set(),
                "databases": set(),
                "first_seen": None,
                "last_seen": None,
            }
        )
        self.database_stats: Dict[str, Dict] = defaultdict(
            lambda: {
                "query_count": 0,
                "tables": set(),
                "users": set(),
            }
        )
        self.query_type_counts: Dict[str, int] = defaultdict(int)
        self.query_patterns: Dict[str, Dict] = defaultdict(
            lambda: {
                "count": 0,
                "examples": [],
                "users": set(),
                "tables": set(),
            }
        )
        self.s3_bucket_stats: Dict[str, Dict] = defaultdict(
            lambda: {
                "get_count": 0,
                "put_count": 0,
                "list_count": 0,
                "bytes_in": 0,
                "bytes_out": 0,
                "users": set(),
            }
        )
        self.hourly_counts: Dict[str, int] = defaultdict(int)
        self.daily_counts: Dict[str, int] = defaultdict(int)

        # Time range
        self.earliest_event: Optional[datetime] = None
        self.latest_event: Optional[datetime] = None

        # SQL Dialect Features
        self.sql_features: Dict[str, int] = defaultdict(int)
        self.sql_feature_examples: Dict[str, List[str]] = defaultdict(list)

        # Failed Queries Tracking
        self.query_status_counts: Dict[str, int] = defaultdict(int)
        self.error_types: Dict[str, int] = defaultdict(int)
        self.error_examples: Dict[str, List[str]] = defaultdict(list)

        # Query Execution Times
        self.execution_times: List[int] = []  # in milliseconds
        self.execution_time_buckets: Dict[str, int] = defaultdict(int)

        # Errors encountered
        self.processing_errors: List[str] = []

        # === MIGRATION RISK ANALYSIS ===

        # Query Complexity Analysis
        self.query_complexity_stats: Dict[str, Dict] = defaultdict(
            lambda: {
                "join_count": 0,
                "cte_count": 0,
                "subquery_depth": 0,
                "union_count": 0,
                "query_text": "",
            }
        )
        self.join_type_counts: Dict[str, int] = defaultdict(int)  # LEFT, RIGHT, INNER, OUTER, CROSS
        self.high_complexity_queries: List[Dict] = []  # Queries with 3+ JOINs or deep nesting
        self.cte_usage_count: int = 0
        self.queries_with_multiple_joins: int = 0

        # DDL Operation Tracking
        self.ddl_operations: List[Dict] = []  # All DDL operations with timestamps
        self.ddl_by_type: Dict[str, int] = defaultdict(int)  # CREATE, DROP, ALTER, TRUNCATE
        self.ddl_by_hour: Dict[int, int] = defaultdict(int)  # Hour of day (0-23)
        self.ddl_by_user: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.tables_with_frequent_ddl: Dict[str, int] = defaultdict(int)

        # Data Scan Analysis
        self.data_scanned_per_query: List[int] = []  # bytes
        self.data_scanned_by_user: Dict[str, int] = defaultdict(int)
        self.data_scanned_by_workgroup: Dict[str, int] = defaultdict(int)
        self.full_table_scans: int = 0  # Queries without WHERE clause

        # Partition Access Patterns
        self.partition_columns_detected: Dict[str, int] = defaultdict(int)
        self.queries_using_partition_filter: int = 0
        self.queries_missing_partition_filter: int = 0
        self.tables_by_estimated_partitions: Dict[str, int] = defaultdict(int)

        # Object/File Size Distribution (from S3 events)
        self.object_sizes: List[int] = []  # bytes
        self.small_file_count: int = 0  # files < 10MB
        self.objects_per_query: List[int] = []

        # Concurrency Patterns
        self.concurrent_queries_by_minute: Dict[str, int] = defaultdict(int)
        self.peak_concurrency: int = 0
        self.queries_by_minute: Dict[str, List[str]] = defaultdict(list)  # minute -> list of query IDs

        # Long-running Query Tracking
        self.long_running_queries: List[Dict] = []  # Queries > 10 minutes
        self.very_long_queries: List[Dict] = []  # Queries > 30 minutes
        self.queries_over_1hr: int = 0

        # SQL Compatibility Flags for Migration
        self.migration_flags: Dict[str, List[Dict]] = defaultdict(list)  # flag -> list of examples

        # Migration Readiness Score Components
        self.readiness_factors: Dict[str, Dict] = {}

    def load_exports(self) -> int:
        """Load all zip files from the exports path. Returns count of files processed."""
        zip_files = []

        # Find all zip files recursively
        if self.exports_path.is_file() and self.exports_path.suffix == ".zip":
            zip_files = [self.exports_path]
        else:
            zip_files = list(self.exports_path.rglob("*.zip"))

        if not zip_files:
            print(f"No zip files found in {self.exports_path}")
            return 0

        print(f"Found {len(zip_files)} export files to process...")

        for zip_path in sorted(zip_files):
            try:
                self._process_zip_file(zip_path)
            except Exception as e:
                self.processing_errors.append(f"Error processing {zip_path}: {str(e)}")

        return len(zip_files)

    def _process_zip_file(self, zip_path: Path) -> None:
        """Process a single zip file and extract data."""
        with zipfile.ZipFile(zip_path, "r") as zf:
            # Load summary.json
            if "summary.json" in zf.namelist():
                with zf.open("summary.json") as f:
                    summary = json.loads(f.read().decode("utf-8"))
                    self.all_summaries.append(summary)
                    self._merge_summary(summary)

            # Load athena_events.json
            if "athena_events.json" in zf.namelist():
                with zf.open("athena_events.json") as f:
                    events = json.loads(f.read().decode("utf-8"))
                    self.all_athena_events.extend(events)
                    self._process_athena_events(events)

            # Load s3_events.json
            if "s3_events.json" in zf.namelist():
                with zf.open("s3_events.json") as f:
                    events = json.loads(f.read().decode("utf-8"))
                    self.all_s3_events.extend(events)
                    self._process_s3_events(events)

    def _merge_summary(self, summary: Dict) -> None:
        """Merge summary data into aggregated statistics."""
        # Merge workgroup stats
        for wg, stats in summary.get("workgroup_stats", {}).items():
            self.workgroup_stats[wg]["query_count"] += stats.get("query_count", 0)
            self.workgroup_stats[wg]["total_data_scanned"] += stats.get(
                "total_data_scanned", 0
            )
            for user in stats.get("users", []):
                self.workgroup_stats[wg]["users"].add(user)
            for qt, count in stats.get("query_types", {}).items():
                self.workgroup_stats[wg]["query_types"][qt] += count
                self.query_type_counts[qt] += count

        # Merge user stats
        for user, stats in summary.get("user_stats", {}).items():
            self.user_stats[user]["query_count"] += stats.get("query_count", 0)
            for wg in stats.get("workgroups", []):
                self.user_stats[user]["workgroups"].add(wg)
            for db in stats.get("databases", []):
                self.user_stats[user]["databases"].add(db)

        # Merge database stats
        for db, stats in summary.get("database_stats", {}).items():
            self.database_stats[db]["query_count"] += stats.get("query_count", 0)
            for table in stats.get("tables", []):
                self.database_stats[db]["tables"].add(table)
            for user in stats.get("users", []):
                self.database_stats[db]["users"].add(user)

        # Merge query patterns
        for pattern_hash, pattern in summary.get("query_patterns", {}).items():
            self.query_patterns[pattern_hash]["count"] += pattern.get("count", 0)

            # Get pattern metadata
            pattern_users = pattern.get("users", [])
            pattern_user = pattern_users[0] if pattern_users else "unknown"
            execution_time_ms = pattern.get("total_execution_time_ms", 0) or 0
            pattern_count = pattern.get("count", 1)
            # Average execution time per query in this pattern
            avg_exec_time = execution_time_ms / max(1, pattern_count)

            for example in pattern.get("examples", []):
                if example not in self.query_patterns[pattern_hash]["examples"]:
                    if len(self.query_patterns[pattern_hash]["examples"]) < 3:
                        self.query_patterns[pattern_hash]["examples"].append(example)

                # Also scan pattern examples for SQL features
                features = self._detect_sql_features(example)
                for feature in features:
                    self.sql_features[feature] += 1
                    if len(self.sql_feature_examples[feature]) < 2:
                        truncated = example[:300] + ("..." if len(example) > 300 else "")
                        self.sql_feature_examples[feature].append(truncated)

                # === MIGRATION RISK ANALYSIS on actual query text ===
                # Analyze query complexity
                self._analyze_query_complexity(example, pattern_hash)

                # Detect DDL operations
                self._detect_ddl_operation(example, pattern_user, "")

                # Analyze partition usage
                self._analyze_partition_usage(example)

                # Track long-running queries (use average execution time for this pattern)
                if avg_exec_time > 0:
                    self._track_long_running_query(example, int(avg_exec_time), pattern_user, "")

                # Detect migration compatibility flags
                flags = self._detect_migration_compatibility_flags(example)
                for flag in flags:
                    if len(self.migration_flags[flag]) < 5:
                        self.migration_flags[flag].append({
                            "query_id": pattern_hash,
                            "user": pattern_user,
                            "query_preview": example[:300],
                        })

            for user in pattern.get("users", []):
                self.query_patterns[pattern_hash]["users"].add(user)
            for table in pattern.get("tables", []):
                self.query_patterns[pattern_hash]["tables"].add(table)

        # Merge S3 bucket stats
        for bucket, stats in summary.get("s3_bucket_stats", {}).items():
            self.s3_bucket_stats[bucket]["get_count"] += stats.get("get_count", 0)
            self.s3_bucket_stats[bucket]["put_count"] += stats.get("put_count", 0)
            self.s3_bucket_stats[bucket]["list_count"] += stats.get("list_count", 0)
            self.s3_bucket_stats[bucket]["bytes_in"] += stats.get("bytes_in", 0)
            self.s3_bucket_stats[bucket]["bytes_out"] += stats.get("bytes_out", 0)
            for user in stats.get("users", []):
                self.s3_bucket_stats[bucket]["users"].add(user)

        # Merge hourly counts
        for hour, count in summary.get("hourly_query_counts", {}).items():
            self.hourly_counts[hour] += count

    def _process_athena_events(self, events: List[Dict]) -> None:
        """Process individual Athena events for detailed analysis."""
        for event in events:
            event_time_str = event.get("event_time", "")
            if event_time_str:
                try:
                    event_time = datetime.fromisoformat(
                        event_time_str.replace("Z", "+00:00")
                    )
                    if self.earliest_event is None or event_time < self.earliest_event:
                        self.earliest_event = event_time
                    if self.latest_event is None or event_time > self.latest_event:
                        self.latest_event = event_time

                    # Track daily counts
                    day_key = event_time.strftime("%Y-%m-%d")
                    self.daily_counts[day_key] += 1
                except ValueError:
                    pass  # Skip events with invalid timestamp format

            # Update user time tracking
            user_id = event.get("user_id", "unknown")
            if event_time_str:
                if self.user_stats[user_id]["first_seen"] is None:
                    self.user_stats[user_id]["first_seen"] = event_time_str
                self.user_stats[user_id]["last_seen"] = event_time_str

            # Process query status and errors
            status = event.get("status", "").upper()
            if status:
                self.query_status_counts[status] += 1
                if status == "FAILED":
                    error_message = event.get("error_message", "") or event.get(
                        "state_change_reason", ""
                    )
                    error_type = self._classify_error_type(error_message)
                    self.error_types[error_type] += 1
                    if error_message and len(self.error_examples[error_type]) < 3:
                        self.error_examples[error_type].append(error_message[:200])

            # Process execution time
            execution_time_ms = event.get("execution_time_ms", 0)
            if execution_time_ms and execution_time_ms > 0:
                self.execution_times.append(execution_time_ms)
                bucket = self._bucket_execution_time(execution_time_ms)
                self.execution_time_buckets[bucket] += 1

            # Detect SQL features from query string
            query_string = event.get("query_string", "") or event.get("query", "")
            if query_string:
                features = self._detect_sql_features(query_string)
                for feature in features:
                    self.sql_features[feature] += 1
                    if len(self.sql_feature_examples[feature]) < 2:
                        # Store a truncated example
                        example = query_string[:300]
                        if len(query_string) > 300:
                            example += "..."
                        self.sql_feature_examples[feature].append(example)

                # === MIGRATION RISK ANALYSIS ===
                query_id = event.get("query_execution_id", "") or event.get("query_id", "")

                # Analyze query complexity
                self._analyze_query_complexity(query_string, query_id)

                # Detect DDL operations
                self._detect_ddl_operation(query_string, user_id, event_time_str)

                # Analyze partition usage
                self._analyze_partition_usage(query_string)

                # Track long-running queries
                if execution_time_ms and execution_time_ms > 0:
                    self._track_long_running_query(query_string, execution_time_ms, user_id, event_time_str)

                # Detect migration compatibility flags
                flags = self._detect_migration_compatibility_flags(query_string)
                for flag in flags:
                    if len(self.migration_flags[flag]) < 5:
                        self.migration_flags[flag].append({
                            "query_id": query_id,
                            "user": user_id,
                            "query_preview": query_string[:300],
                        })

                # Track data scanned
                data_scanned = event.get("data_scanned_bytes", 0) or event.get("data_scanned_in_bytes", 0)
                if data_scanned and data_scanned > 0:
                    self.data_scanned_per_query.append(data_scanned)
                    self.data_scanned_by_user[user_id] += data_scanned
                    # Get workgroup for this query
                    workgroup = event.get("workgroup", "") or event.get("work_group", "")
                    if workgroup:
                        self.data_scanned_by_workgroup[workgroup] += data_scanned

            # Track concurrency by minute
            if event_time_str:
                try:
                    et = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
                    minute_key = et.strftime("%Y-%m-%d %H:%M")
                    self.concurrent_queries_by_minute[minute_key] += 1
                    if self.concurrent_queries_by_minute[minute_key] > self.peak_concurrency:
                        self.peak_concurrency = self.concurrent_queries_by_minute[minute_key]
                except ValueError:
                    pass

    def _process_s3_events(self, events: List[Dict]) -> None:
        """Process individual S3 events."""
        for event in events:
            bucket = event.get("bucket", "")
            event_name = event.get("event_name", "")
            user_id = event.get("user_id", "unknown")
            event_time_str = event.get("event_time", "")

            # Track S3 event time range
            if event_time_str:
                try:
                    event_time = datetime.fromisoformat(
                        event_time_str.replace("Z", "+00:00")
                    )
                    if self.earliest_event is None or event_time < self.earliest_event:
                        self.earliest_event = event_time
                    if self.latest_event is None or event_time > self.latest_event:
                        self.latest_event = event_time
                except ValueError:
                    pass

            if bucket:
                if "Get" in event_name:
                    self.s3_bucket_stats[bucket]["get_count"] += 1
                    # Track bytes read if available
                    bytes_out = event.get("bytes_transferred", 0) or event.get(
                        "additionalEventData", {}
                    ).get("bytesTransferredOut", 0)
                    self.s3_bucket_stats[bucket]["bytes_out"] += bytes_out

                    # Track object size for migration analysis
                    object_size = event.get("object_size", 0) or bytes_out
                    if object_size and object_size > 0:
                        self.object_sizes.append(object_size)
                        if object_size < 10 * 1024 * 1024:  # < 10MB
                            self.small_file_count += 1

                elif "Put" in event_name:
                    self.s3_bucket_stats[bucket]["put_count"] += 1
                    bytes_in = event.get("bytes_transferred", 0) or event.get(
                        "additionalEventData", {}
                    ).get("bytesTransferredIn", 0)
                    self.s3_bucket_stats[bucket]["bytes_in"] += bytes_in

                    # Track object size
                    object_size = event.get("object_size", 0) or bytes_in
                    if object_size and object_size > 0:
                        self.object_sizes.append(object_size)
                        if object_size < 10 * 1024 * 1024:  # < 10MB
                            self.small_file_count += 1

                elif "List" in event_name:
                    self.s3_bucket_stats[bucket]["list_count"] += 1
                self.s3_bucket_stats[bucket]["users"].add(user_id)

    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes into human-readable string."""
        if bytes_val == 0:
            return "0 B"
        units = ["B", "KB", "MB", "GB", "TB", "PB"]
        unit_idx = 0
        val = float(bytes_val)
        while val >= 1024 and unit_idx < len(units) - 1:
            val /= 1024
            unit_idx += 1
        return f"{val:.1f} {units[unit_idx]}"

    def _detect_sql_features(self, query: str) -> List[str]:
        """Detect SQL dialect features in a query string."""
        import re

        features = []
        query_upper = query.upper()

        # CTEs (Common Table Expressions)
        if re.search(r'\bWITH\s+\w+\s+AS\s*\(', query_upper):
            features.append("CTE")

        # Window Functions
        window_funcs = [
            r'\bROW_NUMBER\s*\(',
            r'\bRANK\s*\(',
            r'\bDENSE_RANK\s*\(',
            r'\bNTILE\s*\(',
            r'\bLEAD\s*\(',
            r'\bLAG\s*\(',
            r'\bFIRST_VALUE\s*\(',
            r'\bLAST_VALUE\s*\(',
            r'\bNTH_VALUE\s*\(',
            r'\bOVER\s*\(',
        ]
        for pattern in window_funcs:
            if re.search(pattern, query_upper):
                features.append("Window Functions")
                break

        # UNNEST
        if re.search(r'\bUNNEST\s*\(', query_upper):
            features.append("UNNEST")

        # Lambda expressions (arrow notation and functional patterns)
        if re.search(r'->', query):
            features.append("Lambda Expressions")

        # Array/Map transformation functions (often use lambdas)
        array_funcs = [
            r'\bTRANSFORM\s*\(',
            r'\bFILTER\s*\(',
            r'\bREDUCE\s*\(',
            r'\bZIP_WITH\s*\(',
            r'\bMAP_FILTER\s*\(',
            r'\bMAP_TRANSFORM_KEYS\s*\(',
            r'\bMAP_TRANSFORM_VALUES\s*\(',
        ]
        for pattern in array_funcs:
            if re.search(pattern, query_upper):
                features.append("Array/Map Functions")
                break

        # Trino/Presto-specific functions
        trino_funcs = [
            (r'\bTRY\s*\(', "TRY()"),
            (r'\bTRY_CAST\s*\(', "TRY_CAST()"),
            (r'\bAPPROX_DISTINCT\s*\(', "APPROX_DISTINCT()"),
            (r'\bAPPROX_PERCENTILE\s*\(', "APPROX_PERCENTILE()"),
            (r'\bMAP_AGG\s*\(', "MAP_AGG()"),
            (r'\bARRAY_AGG\s*\(', "ARRAY_AGG()"),
            (r'\bMULTIMAP_AGG\s*\(', "MULTIMAP_AGG()"),
            (r'\bHISTOGRAM\s*\(', "HISTOGRAM()"),
            (r'\bSEQUENCE\s*\(', "SEQUENCE()"),
            (r'\bREPEAT\s*\(', "REPEAT()"),
            (r'\bFROM_UNIXTIME\s*\(', "FROM_UNIXTIME()"),
            (r'\bTO_UNIXTIME\s*\(', "TO_UNIXTIME()"),
            (r'\bDATE_TRUNC\s*\(', "DATE_TRUNC()"),
            (r'\bDATE_ADD\s*\(', "DATE_ADD()"),
            (r'\bDATE_DIFF\s*\(', "DATE_DIFF()"),
            (r'\bJSON_EXTRACT\s*\(', "JSON_EXTRACT()"),
            (r'\bJSON_EXTRACT_SCALAR\s*\(', "JSON_EXTRACT_SCALAR()"),
            (r'\bCAST\s*\([^)]+\s+AS\s+ROW\s*\(', "ROW Type Cast"),
            (r'\bCAST\s*\([^)]+\s+AS\s+ARRAY\s*\(', "ARRAY Type Cast"),
            (r'\bCAST\s*\([^)]+\s+AS\s+MAP\s*\(', "MAP Type Cast"),
        ]
        for pattern, name in trino_funcs:
            if re.search(pattern, query_upper):
                features.append(f"Trino: {name}")

        # Complex types
        if re.search(r'\bARRAY\s*\[', query_upper):
            features.append("Array Literals")
        if re.search(r'\bMAP\s*\(', query_upper) or re.search(r'\bMAP\s*\{', query):
            features.append("Map Literals")
        if re.search(r'\bROW\s*\(', query_upper):
            features.append("Row/Struct Types")

        # GROUPING SETS, CUBE, ROLLUP
        if re.search(r'\bGROUPING\s+SETS\s*\(', query_upper):
            features.append("GROUPING SETS")
        if re.search(r'\bCUBE\s*\(', query_upper):
            features.append("CUBE")
        if re.search(r'\bROLLUP\s*\(', query_upper):
            features.append("ROLLUP")

        # TABLESAMPLE
        if re.search(r'\bTABLESAMPLE\s+', query_upper):
            features.append("TABLESAMPLE")

        # Subqueries in FROM (derived tables)
        if re.search(r'\bFROM\s*\(\s*SELECT\b', query_upper):
            features.append("Derived Tables")

        # CROSS JOIN UNNEST
        if re.search(r'\bCROSS\s+JOIN\s+UNNEST\s*\(', query_upper):
            features.append("CROSS JOIN UNNEST")

        # LATERAL
        if re.search(r'\bLATERAL\s*\(', query_upper):
            features.append("LATERAL")

        return list(set(features))  # Remove duplicates

    # === MIGRATION RISK ANALYSIS METHODS ===

    def _analyze_query_complexity(self, query: str, query_id: str = "") -> Dict:
        """Analyze query complexity for migration readiness assessment."""
        import re

        query_upper = query.upper()
        complexity = {
            "join_count": 0,
            "join_types": [],
            "cte_count": 0,
            "subquery_depth": 0,
            "union_count": 0,
            "has_group_by": False,
            "has_aggregation": False,
            "potential_missing_group_by": False,
        }

        # Count JOINs by type
        join_patterns = [
            (r'\bLEFT\s+OUTER\s+JOIN\b', "LEFT OUTER"),
            (r'\bRIGHT\s+OUTER\s+JOIN\b', "RIGHT OUTER"),
            (r'\bFULL\s+OUTER\s+JOIN\b', "FULL OUTER"),
            (r'\bLEFT\s+JOIN\b', "LEFT"),
            (r'\bRIGHT\s+JOIN\b', "RIGHT"),
            (r'\bINNER\s+JOIN\b', "INNER"),
            (r'\bCROSS\s+JOIN\b', "CROSS"),
            (r'\bJOIN\b', "JOIN"),  # Catch remaining JOINs
        ]

        counted_positions = set()
        for pattern, join_type in join_patterns:
            for match in re.finditer(pattern, query_upper):
                if match.start() not in counted_positions:
                    # Avoid double-counting (e.g., LEFT JOIN counted as both LEFT and JOIN)
                    if join_type == "JOIN" and any(
                        p in query_upper[max(0, match.start() - 10):match.start()]
                        for p in ["LEFT ", "RIGHT ", "INNER ", "CROSS ", "OUTER ", "FULL "]
                    ):
                        continue
                    complexity["join_count"] += 1
                    complexity["join_types"].append(join_type)
                    self.join_type_counts[join_type] += 1
                    counted_positions.add(match.start())

        # Count CTEs
        cte_matches = re.findall(r'\bWITH\s+(\w+)\s+AS\s*\(', query_upper)
        complexity["cte_count"] = len(cte_matches)
        if complexity["cte_count"] > 0:
            self.cte_usage_count += 1

        # Count nested subqueries (estimate depth)
        subquery_count = len(re.findall(r'\(\s*SELECT\b', query_upper))
        complexity["subquery_depth"] = subquery_count

        # Count UNIONs
        complexity["union_count"] = len(re.findall(r'\bUNION\s+(ALL\s+)?', query_upper))

        # Check for GROUP BY
        complexity["has_group_by"] = bool(re.search(r'\bGROUP\s+BY\b', query_upper))

        # Check for aggregations
        agg_funcs = r'\b(COUNT|SUM|AVG|MIN|MAX|ARRAY_AGG|STRING_AGG)\s*\('
        complexity["has_aggregation"] = bool(re.search(agg_funcs, query_upper))

        # Flag potential missing GROUP BY (aggregation without GROUP BY, but not simple counts)
        if complexity["has_aggregation"] and not complexity["has_group_by"]:
            # Check if it's selecting non-aggregated columns too
            if re.search(r'SELECT\s+(?!.*\bCOUNT\s*\(\s*\*\s*\)\s*$)', query_upper):
                complexity["potential_missing_group_by"] = True

        # Track high complexity queries
        if complexity["join_count"] >= 3 or complexity["subquery_depth"] >= 3:
            self.high_complexity_queries.append({
                "query_id": query_id,
                "join_count": complexity["join_count"],
                "join_types": complexity["join_types"],
                "cte_count": complexity["cte_count"],
                "subquery_depth": complexity["subquery_depth"],
                "query_preview": query[:500],
            })

        if complexity["join_count"] >= 2:
            self.queries_with_multiple_joins += 1

        return complexity

    def _detect_ddl_operation(self, query: str, user: str, event_time: str) -> Optional[Dict]:
        """Detect and track DDL operations."""
        import re

        query_upper = query.upper().strip()
        ddl_info = None

        # DDL patterns
        ddl_patterns = [
            (r'^CREATE\s+(OR\s+REPLACE\s+)?(EXTERNAL\s+)?(TABLE|VIEW|SCHEMA|DATABASE)', "CREATE"),
            (r'^DROP\s+(TABLE|VIEW|SCHEMA|DATABASE)', "DROP"),
            (r'^ALTER\s+(TABLE|VIEW|SCHEMA|DATABASE)', "ALTER"),
            (r'^TRUNCATE\s+TABLE', "TRUNCATE"),
            (r'^MSCK\s+REPAIR\s+TABLE', "REPAIR"),
        ]

        for pattern, ddl_type in ddl_patterns:
            if re.match(pattern, query_upper):
                # Extract table name if possible
                table_match = re.search(r'(TABLE|VIEW)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?([`"\']?\w+[`"\']?\.)?([`"\']?\w+[`"\']?)', query_upper)
                table_name = table_match.group(3).strip('`"\'') if table_match else "unknown"

                # Parse hour from event time
                hour = 0
                if event_time:
                    try:
                        dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                        hour = dt.hour
                    except ValueError:
                        pass

                ddl_info = {
                    "type": ddl_type,
                    "table": table_name,
                    "user": user,
                    "event_time": event_time,
                    "hour": hour,
                    "query": query,
                }

                self.ddl_operations.append(ddl_info)
                self.ddl_by_type[ddl_type] += 1
                self.ddl_by_hour[hour] += 1
                self.ddl_by_user[user][ddl_type] += 1
                self.tables_with_frequent_ddl[table_name] += 1

                break

        return ddl_info

    def _analyze_partition_usage(self, query: str) -> Dict:
        """Analyze partition column usage in queries."""
        import re

        query_upper = query.upper()
        result = {
            "has_where_clause": False,
            "potential_partition_filters": [],
            "likely_full_scan": False,
        }

        # Common partition column names
        partition_columns = [
            "partition", "dt", "date", "year", "month", "day",
            "region", "country", "event_date", "created_date",
            "load_date", "process_date", "etl_date", "p_date",
        ]

        # Check for WHERE clause
        result["has_where_clause"] = bool(re.search(r'\bWHERE\b', query_upper))

        if result["has_where_clause"]:
            # Check if any partition-like columns are in WHERE
            for col in partition_columns:
                if re.search(rf'\bWHERE\b.*\b{col.upper()}\s*[=<>]', query_upper):
                    result["potential_partition_filters"].append(col)
                    self.partition_columns_detected[col] += 1

        # Check if it's a SELECT without WHERE (likely full scan)
        if re.match(r'^\s*SELECT\b', query_upper) and not result["has_where_clause"]:
            # But not if it's a LIMIT 1 or small limit
            if not re.search(r'\bLIMIT\s+[1-9]\d{0,1}\b', query_upper):
                result["likely_full_scan"] = True
                self.full_table_scans += 1

        if result["potential_partition_filters"]:
            self.queries_using_partition_filter += 1
        elif result["has_where_clause"]:
            self.queries_missing_partition_filter += 1

        return result

    def _track_long_running_query(self, query: str, execution_time_ms: int, user: str, event_time: str) -> None:
        """Track long-running queries for migration readiness."""
        if execution_time_ms <= 0:
            return

        minutes = execution_time_ms / 60000

        query_info = {
            "execution_time_ms": execution_time_ms,
            "execution_time_min": round(minutes, 1),
            "user": user,
            "event_time": event_time,
            "query_preview": query[:500] if query else "",
        }

        if minutes >= 60:
            self.queries_over_1hr += 1
            self.very_long_queries.append(query_info)
        elif minutes >= 30:
            self.very_long_queries.append(query_info)
        elif minutes >= 10:
            self.long_running_queries.append(query_info)

    def _detect_migration_compatibility_flags(self, query: str) -> List[str]:
        """Detect SQL patterns that may need attention during migration."""
        import re

        flags = []
        query_upper = query.upper()

        # CTAS (Create Table As Select)
        if re.search(r'\bCREATE\s+(EXTERNAL\s+)?TABLE\s+.*\s+AS\s+SELECT\b', query_upper):
            flags.append("CTAS")

        # INSERT INTO with partitions
        if re.search(r'\bINSERT\s+(INTO|OVERWRITE)\s+.*\bPARTITION\s*\(', query_upper):
            flags.append("INSERT_WITH_PARTITION")

        # ACID table operations (Iceberg, Hudi, Delta)
        if re.search(r'\bUSING\s+(ICEBERG|HUDI|DELTA)\b', query_upper):
            flags.append("ACID_TABLE")
        if re.search(r'\bMERGE\s+INTO\b', query_upper):
            flags.append("MERGE_INTO")
        if re.search(r'\bDELETE\s+FROM\b', query_upper):
            flags.append("DELETE_FROM")
        if re.search(r'\bUPDATE\s+\w+\s+SET\b', query_upper):
            flags.append("UPDATE")

        # Geospatial functions
        geo_funcs = [
            r'\bST_\w+\s*\(', r'\bGEOMETRY\b', r'\bPOINT\s*\(',
            r'\bPOLYGON\s*\(', r'\bLINESTRING\s*\(',
        ]
        for pattern in geo_funcs:
            if re.search(pattern, query_upper):
                flags.append("GEOSPATIAL")
                break

        # JSON functions (Athena-specific syntax)
        if re.search(r'\bJSON_EXTRACT\s*\(', query_upper):
            flags.append("JSON_EXTRACT")
        if re.search(r'\$\.', query):  # JSONPath
            flags.append("JSONPATH")

        # Federated queries
        if re.search(r'\bFROM\s+\w+\.\w+\.\w+\.\w+', query_upper):  # catalog.schema.table pattern
            flags.append("FEDERATED_QUERY")

        # Athena-specific UNLOAD
        if re.search(r'\bUNLOAD\s*\(', query_upper):
            flags.append("UNLOAD")

        # EXPLAIN or EXPLAIN ANALYZE
        if re.search(r'^\s*EXPLAIN\b', query_upper):
            flags.append("EXPLAIN")

        # Prepared statements
        if re.search(r'\bPREPARE\b|\bEXECUTE\b|\bDEALLOCATE\b', query_upper):
            flags.append("PREPARED_STATEMENTS")

        return flags

    def _calculate_migration_readiness_score(self) -> Dict:
        """Calculate overall migration readiness score based on all factors."""
        complexity_score = 0
        considerations = []
        readiness_level = "HIGH"

        # Query Complexity (max 30 points)
        high_complexity_pct = (
            len(self.high_complexity_queries) / max(1, len(self.all_athena_events)) * 100
        )
        if high_complexity_pct > 10:
            complexity_score += 30
            considerations.append(f"HIGH: {high_complexity_pct:.1f}% queries have 3+ JOINs or deep nesting")
        elif high_complexity_pct > 5:
            complexity_score += 20
            considerations.append(f"MEDIUM: {high_complexity_pct:.1f}% queries have 3+ JOINs or deep nesting")
        elif high_complexity_pct > 1:
            complexity_score += 10
            considerations.append(f"LOW: {high_complexity_pct:.1f}% queries have 3+ JOINs or deep nesting")

        # DDL Operations (max 20 points)
        total_ddl = sum(self.ddl_by_type.values())
        drop_count = self.ddl_by_type.get("DROP", 0)
        if drop_count > 20:
            complexity_score += 20
            considerations.append(f"HIGH: {drop_count} DROP operations detected - review DDL patterns")
        elif drop_count > 10:
            complexity_score += 15
            considerations.append(f"MEDIUM: {drop_count} DROP operations detected")
        elif drop_count > 5:
            complexity_score += 10
            considerations.append(f"LOW: {drop_count} DROP operations detected")

        # Long-running Queries (max 20 points)
        if self.queries_over_1hr > 5:
            complexity_score += 20
            considerations.append(f"HIGH: {self.queries_over_1hr} queries run over 1 hour")
        elif len(self.very_long_queries) > 10:
            complexity_score += 15
            considerations.append(f"MEDIUM: {len(self.very_long_queries)} queries run over 30 minutes")
        elif len(self.long_running_queries) > 20:
            complexity_score += 10
            considerations.append(f"LOW: {len(self.long_running_queries)} queries run over 10 minutes")

        # Full Table Scans (max 15 points)
        total_selects = sum(1 for e in self.all_athena_events if "SELECT" in str(e.get("query", "")).upper())
        if total_selects > 0:
            scan_pct = self.full_table_scans / total_selects * 100
            if scan_pct > 30:
                complexity_score += 15
                considerations.append(f"HIGH: {scan_pct:.1f}% of SELECT queries appear to be full table scans")
            elif scan_pct > 15:
                complexity_score += 10
                considerations.append(f"MEDIUM: {scan_pct:.1f}% of SELECT queries appear to be full table scans")

        # SQL Compatibility (max 15 points)
        compatibility_issues = 0
        for flag, examples in self.migration_flags.items():
            if flag in ["GEOSPATIAL", "FEDERATED_QUERY", "UNLOAD"]:
                compatibility_issues += len(examples)
        if compatibility_issues > 20:
            complexity_score += 15
            considerations.append(f"HIGH: {compatibility_issues} queries use features requiring migration attention")
        elif compatibility_issues > 5:
            complexity_score += 10
            considerations.append(f"MEDIUM: {compatibility_issues} queries use features requiring migration attention")

        # Determine readiness level (inverted - lower complexity = higher readiness)
        if complexity_score >= 60:
            readiness_level = "LOW"
        elif complexity_score >= 40:
            readiness_level = "MODERATE"
        elif complexity_score >= 20:
            readiness_level = "GOOD"
        else:
            readiness_level = "HIGH"

        self.readiness_factors = {
            "score": 100 - complexity_score,  # Invert: higher score = more ready
            "complexity": complexity_score,
            "level": readiness_level,
            "considerations": considerations,
            "high_complexity_queries": len(self.high_complexity_queries),
            "ddl_operations": total_ddl,
            "drop_operations": self.ddl_by_type.get("DROP", 0),
            "long_running_queries": len(self.long_running_queries) + len(self.very_long_queries),
            "full_table_scans": self.full_table_scans,
            "compatibility_flags": sum(len(v) for v in self.migration_flags.values()),
        }

        return self.readiness_factors

    def _classify_error_type(self, error_message: str) -> str:
        """Classify an error message into a category."""
        error_lower = error_message.lower() if error_message else ""

        if "timeout" in error_lower or "timed out" in error_lower:
            return "Timeout"
        elif "memory" in error_lower or "oom" in error_lower or "out of memory" in error_lower:
            return "Memory Exceeded"
        elif "syntax" in error_lower or "parse" in error_lower:
            return "Syntax Error"
        elif "permission" in error_lower or "access denied" in error_lower or "not authorized" in error_lower:
            return "Permission Denied"
        elif "does not exist" in error_lower or "not found" in error_lower:
            return "Resource Not Found"
        elif "type" in error_lower and ("mismatch" in error_lower or "cannot be" in error_lower):
            return "Type Error"
        elif "division by zero" in error_lower:
            return "Division By Zero"
        elif "limit" in error_lower:
            return "Limit Exceeded"
        elif "cancelled" in error_lower or "canceled" in error_lower:
            return "Query Cancelled"
        elif "internal" in error_lower:
            return "Internal Error"
        else:
            return "Other Error"

    def _bucket_execution_time(self, ms: int) -> str:
        """Categorize execution time into buckets."""
        if ms < 1000:  # < 1s
            return "< 1 second"
        elif ms < 5000:  # 1-5s
            return "1-5 seconds"
        elif ms < 30000:  # 5-30s
            return "5-30 seconds"
        elif ms < 60000:  # 30s-1m
            return "30s - 1 minute"
        elif ms < 300000:  # 1-5m
            return "1-5 minutes"
        elif ms < 600000:  # 5-10m
            return "5-10 minutes"
        else:  # > 10m
            return "> 10 minutes"

    def generate_report(self, output_path: Optional[str] = None) -> str:
        """Generate a comprehensive analysis report."""
        lines = []

        # Header
        lines.append("=" * 80)
        lines.append("ATHENA USAGE ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append("")

        # Time range
        lines.append("ANALYSIS PERIOD")
        lines.append("-" * 40)
        if self.earliest_event:
            lines.append(f"Earliest Event: {self.earliest_event.isoformat()}")
        if self.latest_event:
            lines.append(f"Latest Event:   {self.latest_event.isoformat()}")
        lines.append(f"Export Files:   {len(self.all_summaries)}")
        lines.append("")

        # Overview
        lines.append("OVERVIEW")
        lines.append("-" * 40)
        total_queries = sum(wg["query_count"] for wg in self.workgroup_stats.values())
        total_data_scanned = sum(
            wg["total_data_scanned"] for wg in self.workgroup_stats.values()
        )
        lines.append(f"Total Athena Events:    {len(self.all_athena_events):,}")
        lines.append(f"Total S3 Events:        {len(self.all_s3_events):,}")
        lines.append(f"Total Queries:          {total_queries:,}")
        lines.append(f"Total Data Scanned:     {self._format_bytes(total_data_scanned)}")
        lines.append(f"Unique Users:           {len(self.user_stats)}")
        lines.append(f"Unique Workgroups:      {len(self.workgroup_stats)}")
        lines.append(f"Unique Databases:       {len(self.database_stats)}")
        lines.append(f"Unique Query Patterns:  {len(self.query_patterns)}")
        lines.append(f"S3 Buckets Accessed:    {len(self.s3_bucket_stats)}")
        lines.append("")

        # Query Types Summary
        lines.append("QUERY TYPES DISTRIBUTION")
        lines.append("-" * 40)
        sorted_types = sorted(self.query_type_counts.items(), key=lambda x: -x[1])
        total_typed = sum(self.query_type_counts.values())
        for qt, count in sorted_types:
            pct = (count / total_typed * 100) if total_typed > 0 else 0
            bar = "█" * int(pct / 2)
            lines.append(f"  {qt:20} {count:8,} ({pct:5.1f}%) {bar}")
        lines.append("")

        # Workgroup Analysis
        lines.append("WORKGROUP ANALYSIS")
        lines.append("-" * 40)
        sorted_workgroups = sorted(
            self.workgroup_stats.items(), key=lambda x: -x[1]["query_count"]
        )
        for wg, stats in sorted_workgroups[:10]:
            lines.append(f"\n  Workgroup: {wg}")
            lines.append(f"    Queries:      {stats['query_count']:,}")
            lines.append(f"    Users:        {len(stats['users'])}")
            lines.append(
                f"    Data Scanned: {self._format_bytes(stats['total_data_scanned'])}"
            )
            if stats["query_types"]:
                top_types = sorted(stats["query_types"].items(), key=lambda x: -x[1])[
                    :3
                ]
                types_str = ", ".join(f"{t}:{c}" for t, c in top_types)
                lines.append(f"    Top Types:    {types_str}")
        lines.append("")

        # Top Users
        lines.append("TOP USERS BY QUERY COUNT")
        lines.append("-" * 40)
        sorted_users = sorted(
            self.user_stats.items(), key=lambda x: -x[1]["query_count"]
        )[:15]
        for user, stats in sorted_users:
            wg_list = ", ".join(list(stats["workgroups"])[:3])
            if len(stats["workgroups"]) > 3:
                wg_list += "..."
            lines.append(
                f"  {user[:40]:40} {stats['query_count']:8,} queries  [{wg_list}]"
            )
        lines.append("")

        # Database Usage
        lines.append("DATABASE USAGE")
        lines.append("-" * 40)
        sorted_databases = sorted(
            self.database_stats.items(), key=lambda x: -x[1]["query_count"]
        )[:10]
        for db, stats in sorted_databases:
            table_count = len(stats["tables"])
            lines.append(
                f"  {db:30} {stats['query_count']:8,} queries, {table_count} tables"
            )
        lines.append("")

        # All Query Patterns (sorted by frequency)
        lines.append("QUERY PATTERNS (by frequency)")
        lines.append("-" * 40)
        sorted_patterns = sorted(
            self.query_patterns.items(), key=lambda x: -x[1]["count"]
        )
        for i, (pattern_hash, pattern) in enumerate(sorted_patterns, 1):
            lines.append(f"\n  Pattern #{i} (Hash: {pattern_hash})")
            lines.append(f"    Executions: {pattern['count']:,}")
            lines.append(f"    Users:      {len(pattern['users'])}")
            if pattern["tables"]:
                tables_str = ", ".join(list(pattern["tables"])[:5])
                lines.append(f"    Tables:     {tables_str}")
            if pattern["examples"]:
                example = pattern["examples"][0][:200]
                if len(pattern["examples"][0]) > 200:
                    example += "..."
                lines.append(f"    Example:    {example}")
        lines.append("")

        # S3 Bucket Analysis
        if self.s3_bucket_stats:
            lines.append("S3 BUCKET ACCESS ANALYSIS")
            lines.append("-" * 40)
            total_s3_ops = sum(
                s["get_count"] + s["put_count"] + s["list_count"]
                for s in self.s3_bucket_stats.values()
            )
            total_bytes_in = sum(s["bytes_in"] for s in self.s3_bucket_stats.values())
            total_bytes_out = sum(s["bytes_out"] for s in self.s3_bucket_stats.values())
            lines.append(f"Total S3 Operations: {total_s3_ops:,}")
            lines.append(f"Total Data Read:     {self._format_bytes(total_bytes_out)}")
            lines.append(f"Total Data Written:  {self._format_bytes(total_bytes_in)}")
            sorted_buckets = sorted(
                self.s3_bucket_stats.items(),
                key=lambda x: -(
                    x[1]["get_count"] + x[1]["put_count"] + x[1]["list_count"]
                ),
            )[:10]
            for bucket, stats in sorted_buckets:
                total_ops = (
                    stats["get_count"] + stats["put_count"] + stats["list_count"]
                )
                lines.append(f"\n  Bucket: {bucket}")
                lines.append(f"    GET:   {stats['get_count']:,}")
                lines.append(f"    PUT:   {stats['put_count']:,}")
                lines.append(f"    LIST:  {stats['list_count']:,}")
                lines.append(f"    Total: {total_ops:,}")
                lines.append(f"    Data Read:    {self._format_bytes(stats['bytes_out'])}")
                lines.append(f"    Data Written: {self._format_bytes(stats['bytes_in'])}")
                lines.append(f"    Users: {len(stats['users'])}")
            lines.append("")

        # Daily Activity
        if self.daily_counts:
            lines.append("DAILY ACTIVITY")
            lines.append("-" * 40)
            sorted_days = sorted(self.daily_counts.items())
            max_count = max(self.daily_counts.values()) if self.daily_counts else 1
            for day, count in sorted_days[-14:]:  # Last 14 days
                bar_len = int(count / max_count * 40)
                bar = "█" * bar_len
                lines.append(f"  {day}: {count:6,} {bar}")
            lines.append("")

        # SQL Dialect Features
        if self.sql_features:
            lines.append("SQL DIALECT FEATURES DETECTED")
            lines.append("-" * 40)
            sorted_features = sorted(self.sql_features.items(), key=lambda x: -x[1])
            for feature, count in sorted_features[:20]:
                lines.append(f"  {feature:35} {count:8,} occurrences")
            lines.append("")

        # Query Status & Failed Queries
        if self.query_status_counts:
            lines.append("QUERY STATUS SUMMARY")
            lines.append("-" * 40)
            total_with_status = sum(self.query_status_counts.values())
            for status, count in sorted(
                self.query_status_counts.items(), key=lambda x: -x[1]
            ):
                pct = (count / total_with_status * 100) if total_with_status > 0 else 0
                lines.append(f"  {status:20} {count:8,} ({pct:5.1f}%)")
            lines.append("")

            if self.error_types:
                lines.append("FAILED QUERY ERROR TYPES")
                lines.append("-" * 40)
                for error_type, count in sorted(
                    self.error_types.items(), key=lambda x: -x[1]
                ):
                    lines.append(f"  {error_type:30} {count:8,}")
                    if error_type in self.error_examples:
                        for example in self.error_examples[error_type][:1]:
                            lines.append(f"      Example: {example[:100]}...")
                lines.append("")

        # Query Execution Time Distribution
        if self.execution_time_buckets:
            lines.append("QUERY EXECUTION TIME DISTRIBUTION")
            lines.append("-" * 40)
            bucket_order = [
                "< 1 second",
                "1-5 seconds",
                "5-30 seconds",
                "30s - 1 minute",
                "1-5 minutes",
                "5-10 minutes",
                "> 10 minutes",
            ]
            total_timed = sum(self.execution_time_buckets.values())
            for bucket in bucket_order:
                count = self.execution_time_buckets.get(bucket, 0)
                pct = (count / total_timed * 100) if total_timed > 0 else 0
                bar = "█" * int(pct / 2)
                lines.append(f"  {bucket:18} {count:8,} ({pct:5.1f}%) {bar}")

            if self.execution_times:
                avg_ms = sum(self.execution_times) / len(self.execution_times)
                min_ms = min(self.execution_times)
                max_ms = max(self.execution_times)
                sorted_times = sorted(self.execution_times)
                p50_ms = sorted_times[len(sorted_times) // 2]
                p95_idx = int(len(sorted_times) * 0.95)
                p95_ms = sorted_times[p95_idx] if p95_idx < len(sorted_times) else max_ms

                lines.append("")
                lines.append("  Execution Time Statistics:")
                lines.append(f"    Min:    {min_ms:>10,} ms ({min_ms/1000:.1f}s)")
                lines.append(f"    Avg:    {avg_ms:>10,.0f} ms ({avg_ms/1000:.1f}s)")
                lines.append(f"    P50:    {p50_ms:>10,} ms ({p50_ms/1000:.1f}s)")
                lines.append(f"    P95:    {p95_ms:>10,} ms ({p95_ms/1000:.1f}s)")
                lines.append(f"    Max:    {max_ms:>10,} ms ({max_ms/1000:.1f}s)")
            lines.append("")

        # Processing Errors
        if self.processing_errors:
            lines.append("PROCESSING ERRORS")
            lines.append("-" * 40)
            for error in self.processing_errors:
                lines.append(f"  - {error}")
            lines.append("")

        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)

        report = "\n".join(lines)

        # Save report if output path specified
        if output_path:
            with open(output_path, "w") as f:
                f.write(report)
            print(f"Report saved to: {output_path}")

        return report

    def generate_graphs(self, output_dir: str = ".") -> List[str]:
        """Generate visualization graphs. Returns list of generated file paths."""
        if not HAS_MATPLOTLIB:
            print("Skipping graph generation (matplotlib not available)")
            return []

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        generated_files = []

        # Set style
        plt.style.use("default")

        # 1. Query Types Pie Chart
        if self.query_type_counts:
            fig, ax = plt.subplots(figsize=(10, 8))
            sorted_types = sorted(self.query_type_counts.items(), key=lambda x: -x[1])
            labels = [t[0] for t in sorted_types]
            sizes = [t[1] for t in sorted_types]

            # Only show top 8, group rest as "Other"
            if len(labels) > 8:
                other_count = sum(sizes[8:])
                labels = labels[:8] + ["Other"]
                sizes = sizes[:8] + [other_count]

            colors = plt.cm.Set3(range(len(labels)))
            wedges, texts, autotexts = ax.pie(
                sizes, labels=labels, autopct="%1.1f%%", colors=colors, startangle=90
            )
            ax.set_title("Query Types Distribution", fontsize=14, fontweight="bold")

            filepath = output_path / "query_types_distribution.png"
            plt.savefig(filepath, dpi=150, bbox_inches="tight")
            plt.close()
            generated_files.append(str(filepath))

        # 2. Daily Activity Bar Chart
        if self.daily_counts:
            fig, ax = plt.subplots(figsize=(14, 6))
            sorted_days = sorted(self.daily_counts.items())[-30:]  # Last 30 days
            days = [d[0] for d in sorted_days]
            counts = [d[1] for d in sorted_days]

            ax.bar(range(len(days)), counts, color="steelblue", edgecolor="navy")
            ax.set_xticks(range(len(days)))
            ax.set_xticklabels(days, rotation=45, ha="right", fontsize=8)
            ax.set_xlabel("Date")
            ax.set_ylabel("Event Count")
            ax.set_title("Daily Athena Activity", fontsize=14, fontweight="bold")
            ax.grid(axis="y", alpha=0.3)

            filepath = output_path / "daily_activity.png"
            plt.savefig(filepath, dpi=150, bbox_inches="tight")
            plt.close()
            generated_files.append(str(filepath))

        # 3. Workgroup Query Distribution
        if self.workgroup_stats:
            fig, ax = plt.subplots(figsize=(12, 6))
            sorted_wgs = sorted(
                self.workgroup_stats.items(), key=lambda x: -x[1]["query_count"]
            )[:10]
            workgroups = [w[0][:20] for w in sorted_wgs]
            query_counts = [w[1]["query_count"] for w in sorted_wgs]

            bars = ax.barh(range(len(workgroups)), query_counts, color="teal")
            ax.set_yticks(range(len(workgroups)))
            ax.set_yticklabels(workgroups)
            ax.set_xlabel("Query Count")
            ax.set_title(
                "Top Workgroups by Query Count", fontsize=14, fontweight="bold"
            )
            ax.invert_yaxis()
            ax.grid(axis="x", alpha=0.3)

            # Add value labels
            for bar, count in zip(bars, query_counts):
                ax.text(
                    bar.get_width() + max(query_counts) * 0.01,
                    bar.get_y() + bar.get_height() / 2,
                    f"{count:,}",
                    va="center",
                    fontsize=9,
                )

            filepath = output_path / "workgroup_queries.png"
            plt.savefig(filepath, dpi=150, bbox_inches="tight")
            plt.close()
            generated_files.append(str(filepath))

        # 4. Data Scanned by Workgroup
        if self.workgroup_stats:
            fig, ax = plt.subplots(figsize=(12, 6))
            sorted_wgs = sorted(
                self.workgroup_stats.items(), key=lambda x: -x[1]["total_data_scanned"]
            )[:10]
            workgroups = [w[0][:20] for w in sorted_wgs]
            data_scanned_gb = [
                w[1]["total_data_scanned"] / (1024**3) for w in sorted_wgs
            ]

            bars = ax.barh(range(len(workgroups)), data_scanned_gb, color="coral")
            ax.set_yticks(range(len(workgroups)))
            ax.set_yticklabels(workgroups)
            ax.set_xlabel("Data Scanned (GB)")
            ax.set_title("Data Scanned by Workgroup", fontsize=14, fontweight="bold")
            ax.invert_yaxis()
            ax.grid(axis="x", alpha=0.3)

            # Add value labels
            for bar, gb in zip(bars, data_scanned_gb):
                ax.text(
                    bar.get_width() + max(data_scanned_gb) * 0.01,
                    bar.get_y() + bar.get_height() / 2,
                    f"{gb:.1f} GB",
                    va="center",
                    fontsize=9,
                )

            filepath = output_path / "data_scanned_by_workgroup.png"
            plt.savefig(filepath, dpi=150, bbox_inches="tight")
            plt.close()
            generated_files.append(str(filepath))

        # 5. Top Users Bar Chart
        if self.user_stats:
            fig, ax = plt.subplots(figsize=(12, 6))
            sorted_users = sorted(
                self.user_stats.items(), key=lambda x: -x[1]["query_count"]
            )[:15]
            users = [u[0][:25] for u in sorted_users]
            query_counts = [u[1]["query_count"] for u in sorted_users]

            bars = ax.barh(range(len(users)), query_counts, color="mediumpurple")
            ax.set_yticks(range(len(users)))
            ax.set_yticklabels(users, fontsize=8)
            ax.set_xlabel("Query Count")
            ax.set_title("Top Users by Query Count", fontsize=14, fontweight="bold")
            ax.invert_yaxis()
            ax.grid(axis="x", alpha=0.3)

            filepath = output_path / "top_users.png"
            plt.savefig(filepath, dpi=150, bbox_inches="tight")
            plt.close()
            generated_files.append(str(filepath))

        # 6. S3 Bucket Operations
        if self.s3_bucket_stats:
            fig, ax = plt.subplots(figsize=(12, 8))
            sorted_buckets = sorted(
                self.s3_bucket_stats.items(),
                key=lambda x: -(
                    x[1]["get_count"] + x[1]["put_count"] + x[1]["list_count"]
                ),
            )[:10]

            buckets = [b[0][:30] for b in sorted_buckets]
            gets = [b[1]["get_count"] for b in sorted_buckets]
            puts = [b[1]["put_count"] for b in sorted_buckets]
            lists = [b[1]["list_count"] for b in sorted_buckets]

            x = range(len(buckets))
            width = 0.25

            ax.barh(
                [i - width for i in x], gets, width, label="GET", color="forestgreen"
            )
            ax.barh([i for i in x], puts, width, label="PUT", color="dodgerblue")
            ax.barh([i + width for i in x], lists, width, label="LIST", color="orange")

            ax.set_yticks(x)
            ax.set_yticklabels(buckets, fontsize=8)
            ax.set_xlabel("Operation Count")
            ax.set_title("S3 Bucket Operations", fontsize=14, fontweight="bold")
            ax.legend()
            ax.invert_yaxis()
            ax.grid(axis="x", alpha=0.3)

            filepath = output_path / "s3_bucket_operations.png"
            plt.savefig(filepath, dpi=150, bbox_inches="tight")
            plt.close()
            generated_files.append(str(filepath))

        # 7. Query Pattern Frequency
        if self.query_patterns:
            fig, ax = plt.subplots(figsize=(10, 6))
            sorted_patterns = sorted(
                self.query_patterns.items(), key=lambda x: -x[1]["count"]
            )[:15]

            pattern_labels = [f"Pattern {i + 1}" for i in range(len(sorted_patterns))]
            counts = [p[1]["count"] for p in sorted_patterns]

            bars = ax.bar(range(len(pattern_labels)), counts, color="indianred")
            ax.set_xticks(range(len(pattern_labels)))
            ax.set_xticklabels(pattern_labels, rotation=45, ha="right")
            ax.set_ylabel("Execution Count")
            ax.set_title(
                "Top 15 Query Patterns by Frequency", fontsize=14, fontweight="bold"
            )
            ax.grid(axis="y", alpha=0.3)

            filepath = output_path / "query_patterns.png"
            plt.savefig(filepath, dpi=150, bbox_inches="tight")
            plt.close()
            generated_files.append(str(filepath))

        print(f"Generated {len(generated_files)} graphs in {output_dir}/")
        return generated_files

    def generate_html_report(self, output_path: str) -> None:
        """Generate an HTML report with embedded graphs."""
        import base64

        # Generate graphs to memory
        graph_data = {}

        if HAS_MATPLOTLIB:
            # Generate each graph and capture as base64
            graphs_to_generate = [
                ("query_types", self._generate_query_types_graph),
                ("daily_activity", self._generate_daily_activity_graph),
                ("workgroup_queries", self._generate_workgroup_queries_graph),
                ("data_scanned", self._generate_data_scanned_graph),
                ("top_users", self._generate_top_users_graph),
                ("s3_operations", self._generate_s3_operations_graph),
                ("sql_features", self._generate_sql_features_graph),
                ("query_status", self._generate_query_status_graph),
                ("execution_time", self._generate_execution_time_graph),
            ]

            for name, generator in graphs_to_generate:
                try:
                    img_data = generator()
                    if img_data:
                        graph_data[name] = base64.b64encode(img_data).decode("utf-8")
                except Exception as e:
                    print(f"Error generating {name} graph: {e}")

        # Build HTML
        html = self._build_html_report(graph_data)

        with open(output_path, "w") as f:
            f.write(html)

        print(f"HTML report saved to: {output_path}")

    def _generate_query_types_graph(self) -> Optional[bytes]:
        """Generate query types horizontal bar chart for better readability."""
        if not self.query_type_counts:
            return None

        fig, ax = plt.subplots(figsize=(10, 6))
        sorted_types = sorted(self.query_type_counts.items(), key=lambda x: x[1])
        labels = [t[0] for t in sorted_types]
        sizes = [t[1] for t in sorted_types]
        total = sum(sizes)

        # Calculate percentages for labels
        percentages = [s / total * 100 for s in sizes]

        # Create horizontal bar chart
        colors = plt.cm.Set3(range(len(labels)))
        bars = ax.barh(range(len(labels)), sizes, color=colors)

        # Add value labels on bars
        for i, (bar, pct, count) in enumerate(zip(bars, percentages, sizes)):
            width = bar.get_width()
            label = f"{count:,} ({pct:.1f}%)"
            # Place label inside or outside bar depending on width
            if pct > 15:
                ax.text(width / 2, bar.get_y() + bar.get_height() / 2,
                        label, ha="center", va="center", fontsize=9, fontweight="bold")
            else:
                ax.text(width + total * 0.01, bar.get_y() + bar.get_height() / 2,
                        label, ha="left", va="center", fontsize=9)

        ax.set_yticks(range(len(labels)))
        ax.set_yticklabels(labels, fontsize=10)
        ax.set_xlabel("Count")
        ax.set_title("Query Types Distribution", fontsize=14, fontweight="bold")
        ax.grid(axis="x", alpha=0.3)

        # Extend x-axis a bit for labels
        ax.set_xlim(0, max(sizes) * 1.15)

        plt.tight_layout()
        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=100, bbox_inches="tight")
        plt.close()
        buf.seek(0)
        return buf.getvalue()

    def _generate_daily_activity_graph(self) -> Optional[bytes]:
        """Generate daily activity bar chart."""
        if not self.daily_counts:
            return None

        fig, ax = plt.subplots(figsize=(12, 4))
        sorted_days = sorted(self.daily_counts.items())[-30:]
        days = [d[0] for d in sorted_days]
        counts = [d[1] for d in sorted_days]

        ax.bar(range(len(days)), counts, color="steelblue")
        ax.set_xticks(range(len(days)))
        ax.set_xticklabels(days, rotation=45, ha="right", fontsize=7)
        ax.set_ylabel("Events")
        ax.set_title("Daily Activity (Last 30 Days)")
        ax.grid(axis="y", alpha=0.3)

        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=100, bbox_inches="tight")
        plt.close()
        buf.seek(0)
        return buf.getvalue()

    def _generate_workgroup_queries_graph(self) -> Optional[bytes]:
        """Generate workgroup queries bar chart."""
        if not self.workgroup_stats:
            return None

        fig, ax = plt.subplots(figsize=(10, 5))
        sorted_wgs = sorted(
            self.workgroup_stats.items(), key=lambda x: -x[1]["query_count"]
        )[:10]
        workgroups = [w[0][:20] for w in sorted_wgs]
        counts = [w[1]["query_count"] for w in sorted_wgs]

        ax.barh(range(len(workgroups)), counts, color="teal")
        ax.set_yticks(range(len(workgroups)))
        ax.set_yticklabels(workgroups)
        ax.set_xlabel("Query Count")
        ax.set_title("Top Workgroups by Query Count")
        ax.invert_yaxis()
        ax.grid(axis="x", alpha=0.3)

        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=100, bbox_inches="tight")
        plt.close()
        buf.seek(0)
        return buf.getvalue()

    def _generate_data_scanned_graph(self) -> Optional[bytes]:
        """Generate data scanned bar chart."""
        if not self.workgroup_stats:
            return None

        fig, ax = plt.subplots(figsize=(10, 5))
        sorted_wgs = sorted(
            self.workgroup_stats.items(), key=lambda x: -x[1]["total_data_scanned"]
        )[:10]
        workgroups = [w[0][:20] for w in sorted_wgs]
        data_gb = [w[1]["total_data_scanned"] / (1024**3) for w in sorted_wgs]

        ax.barh(range(len(workgroups)), data_gb, color="coral")
        ax.set_yticks(range(len(workgroups)))
        ax.set_yticklabels(workgroups)
        ax.set_xlabel("Data Scanned (GB)")
        ax.set_title("Data Scanned by Workgroup")
        ax.invert_yaxis()
        ax.grid(axis="x", alpha=0.3)

        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=100, bbox_inches="tight")
        plt.close()
        buf.seek(0)
        return buf.getvalue()

    def _generate_top_users_graph(self) -> Optional[bytes]:
        """Generate top users bar chart."""
        if not self.user_stats:
            return None

        fig, ax = plt.subplots(figsize=(10, 5))
        sorted_users = sorted(
            self.user_stats.items(), key=lambda x: -x[1]["query_count"]
        )[:10]
        users = [u[0][:25] for u in sorted_users]
        counts = [u[1]["query_count"] for u in sorted_users]

        ax.barh(range(len(users)), counts, color="mediumpurple")
        ax.set_yticks(range(len(users)))
        ax.set_yticklabels(users, fontsize=8)
        ax.set_xlabel("Query Count")
        ax.set_title("Top Users by Query Count")
        ax.invert_yaxis()
        ax.grid(axis="x", alpha=0.3)

        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=100, bbox_inches="tight")
        plt.close()
        buf.seek(0)
        return buf.getvalue()

    def _generate_s3_operations_graph(self) -> Optional[bytes]:
        """Generate S3 operations bar chart."""
        if not self.s3_bucket_stats:
            return None

        fig, ax = plt.subplots(figsize=(12, 6))
        sorted_buckets = sorted(
            self.s3_bucket_stats.items(),
            key=lambda x: -(x[1]["get_count"] + x[1]["put_count"] + x[1]["list_count"]),
        )[:8]

        # Show full bucket names (up to 60 chars) for better readability
        buckets = [b[0][:60] + ("..." if len(b[0]) > 60 else "") for b in sorted_buckets]
        gets = [b[1]["get_count"] for b in sorted_buckets]
        puts = [b[1]["put_count"] for b in sorted_buckets]
        lists = [b[1]["list_count"] for b in sorted_buckets]

        x = range(len(buckets))
        width = 0.25

        ax.barh([i - width for i in x], gets, width, label="GET", color="forestgreen")
        ax.barh([i for i in x], puts, width, label="PUT", color="dodgerblue")
        ax.barh([i + width for i in x], lists, width, label="LIST", color="orange")

        ax.set_yticks(x)
        ax.set_yticklabels(buckets, fontsize=9)
        ax.set_xlabel("Operation Count")
        ax.set_title("S3 Bucket Operations", fontsize=14, fontweight="bold")
        ax.legend(loc="lower right")
        ax.invert_yaxis()
        ax.grid(axis="x", alpha=0.3)

        plt.tight_layout()
        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=100, bbox_inches="tight")
        plt.close()
        buf.seek(0)
        return buf.getvalue()

    def _generate_sql_features_graph(self) -> Optional[bytes]:
        """Generate SQL dialect features bar chart."""
        if not self.sql_features:
            return None

        fig, ax = plt.subplots(figsize=(10, 6))
        sorted_features = sorted(self.sql_features.items(), key=lambda x: -x[1])[:12]

        features = [f[0][:30] for f in sorted_features]
        counts = [f[1] for f in sorted_features]

        colors = plt.cm.viridis([i / len(features) for i in range(len(features))])
        ax.barh(range(len(features)), counts, color=colors)
        ax.set_yticks(range(len(features)))
        ax.set_yticklabels(features, fontsize=9)
        ax.set_xlabel("Occurrences")
        ax.set_title("SQL Dialect Features Detected")
        ax.invert_yaxis()
        ax.grid(axis="x", alpha=0.3)

        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=100, bbox_inches="tight")
        plt.close()
        buf.seek(0)
        return buf.getvalue()

    def _generate_query_status_graph(self) -> Optional[bytes]:
        """Generate query status pie chart."""
        if not self.query_status_counts:
            return None

        fig, ax = plt.subplots(figsize=(8, 6))
        statuses = list(self.query_status_counts.keys())
        counts = list(self.query_status_counts.values())

        # Use colors that indicate success/failure
        color_map = {
            "SUCCEEDED": "#28a745",
            "FAILED": "#dc3545",
            "CANCELLED": "#ffc107",
            "RUNNING": "#17a2b8",
            "QUEUED": "#6c757d",
        }
        colors = [color_map.get(s, "#6c757d") for s in statuses]

        wedges, texts, autotexts = ax.pie(
            counts,
            labels=statuses,
            autopct="%1.1f%%",
            colors=colors,
            startangle=90,
        )
        ax.set_title("Query Status Distribution")

        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=100, bbox_inches="tight")
        plt.close()
        buf.seek(0)
        return buf.getvalue()

    def _generate_execution_time_graph(self) -> Optional[bytes]:
        """Generate execution time distribution bar chart."""
        if not self.execution_time_buckets:
            return None

        fig, ax = plt.subplots(figsize=(10, 5))
        bucket_order = [
            "< 1 second",
            "1-5 seconds",
            "5-30 seconds",
            "30s - 1 minute",
            "1-5 minutes",
            "5-10 minutes",
            "> 10 minutes",
        ]
        counts = [self.execution_time_buckets.get(b, 0) for b in bucket_order]

        # Color gradient from green (fast) to red (slow)
        colors = ["#28a745", "#5cb85c", "#8bc34a", "#ffc107", "#ff9800", "#ff5722", "#dc3545"]

        bars = ax.bar(range(len(bucket_order)), counts, color=colors)
        ax.set_xticks(range(len(bucket_order)))
        ax.set_xticklabels(bucket_order, rotation=30, ha="right", fontsize=9)
        ax.set_ylabel("Query Count")
        ax.set_title("Query Execution Time Distribution")
        ax.grid(axis="y", alpha=0.3)

        # Add value labels on bars
        for bar, count in zip(bars, counts):
            if count > 0:
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + max(counts) * 0.01,
                    f"{count:,}",
                    ha="center",
                    va="bottom",
                    fontsize=8,
                )

        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=100, bbox_inches="tight")
        plt.close()
        buf.seek(0)
        return buf.getvalue()

    def _build_html_report(self, graph_data: Dict[str, str]) -> str:
        """Build the HTML report content."""
        total_queries = sum(wg["query_count"] for wg in self.workgroup_stats.values())
        total_data_scanned = sum(
            wg["total_data_scanned"] for wg in self.workgroup_stats.values()
        )
        total_data_scanned_str = self._format_bytes(total_data_scanned)
        total_s3_ops = sum(
            s["get_count"] + s["put_count"] + s["list_count"]
            for s in self.s3_bucket_stats.values()
        )
        total_s3_bytes_in = sum(s["bytes_in"] for s in self.s3_bucket_stats.values())
        total_s3_bytes_out = sum(s["bytes_out"] for s in self.s3_bucket_stats.values())

        # Calculate time range info
        time_range_str = "Unknown"
        duration_str = ""
        avg_queries_per_day = 0
        if self.earliest_event and self.latest_event:
            time_range_str = f"{self.earliest_event.strftime('%Y-%m-%d %H:%M')} to {self.latest_event.strftime('%Y-%m-%d %H:%M')} UTC"
            duration = self.latest_event - self.earliest_event
            days = duration.days
            hours = duration.seconds // 3600
            if days > 0:
                duration_str = f"{days} day{'s' if days != 1 else ''}"
                if hours > 0:
                    duration_str += f", {hours} hour{'s' if hours != 1 else ''}"
            else:
                duration_str = f"{hours} hour{'s' if hours != 1 else ''}"
            if days > 0:
                avg_queries_per_day = total_queries / max(days, 1)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Athena Usage Analysis Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #232f3e; border-bottom: 3px solid #ff9900; padding-bottom: 10px; }}
        h2 {{ color: #232f3e; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }}
        .card {{ background: white; border-radius: 8px; padding: 20px; margin: 15px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; }}
        .stat-box {{ background: linear-gradient(135deg, #232f3e, #37475a); color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-box .value {{ font-size: 1.8em; font-weight: bold; color: #ff9900; }}
        .stat-box .label {{ font-size: 0.9em; opacity: 0.9; }}
        .time-range {{ background: linear-gradient(135deg, #1a5276, #2980b9); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .time-range h3 {{ margin: 0 0 10px 0; color: #f1c40f; }}
        .time-range .period {{ font-size: 1.1em; margin: 5px 0; }}
        .time-range .duration {{ font-size: 0.95em; opacity: 0.9; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #232f3e; color: white; }}
        tr:hover {{ background: #f9f9f9; }}
        .graph {{ text-align: center; margin: 20px 0; }}
        .graph img {{ max-width: 100%; height: auto; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .query-example {{ background: #f8f8f8; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.85em; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
        .footer {{ text-align: center; margin-top: 40px; color: #666; font-size: 0.9em; }}
        .volume-section {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 15px; }}
        .volume-card {{ background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #ff9900; }}
        .volume-card h4 {{ margin: 0 0 10px 0; color: #232f3e; }}
        .volume-card .metric {{ display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px solid #eee; }}
        .volume-card .metric:last-child {{ border-bottom: none; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Athena Usage Analysis Report</h1>

        <div class="card">
            <div class="time-range">
                <h3>Analysis Period</h3>
                <div class="period">{time_range_str}</div>
                <div class="duration">Duration: {duration_str} | Export Files: {len(self.all_summaries)}</div>
            </div>

            <h2 style="margin-top: 0;">Overview</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="value">{len(self.all_athena_events):,}</div>
                    <div class="label">Athena Events</div>
                </div>
                <div class="stat-box">
                    <div class="value">{total_queries:,}</div>
                    <div class="label">Total Queries</div>
                </div>
                <div class="stat-box">
                    <div class="value">{total_data_scanned_str}</div>
                    <div class="label">Data Scanned</div>
                </div>
                <div class="stat-box">
                    <div class="value">{len(self.user_stats)}</div>
                    <div class="label">Unique Users</div>
                </div>
                <div class="stat-box">
                    <div class="value">{len(self.workgroup_stats)}</div>
                    <div class="label">Workgroups</div>
                </div>
                <div class="stat-box">
                    <div class="value">{len(self.s3_bucket_stats)}</div>
                    <div class="label">S3 Buckets</div>
                </div>
                <div class="stat-box">
                    <div class="value">{total_s3_ops:,}</div>
                    <div class="label">S3 Operations</div>
                </div>
                <div class="stat-box">
                    <div class="value">{len(self.query_patterns)}</div>
                    <div class="label">Query Patterns</div>
                </div>
            </div>

            <div class="volume-section">
                <div class="volume-card">
                    <h4>Athena Volume Metrics</h4>
                    <div class="metric"><span>Total Data Scanned</span><strong>{total_data_scanned_str}</strong></div>
                    <div class="metric"><span>Avg Queries/Day</span><strong>{avg_queries_per_day:.1f}</strong></div>
                    <div class="metric"><span>Unique Databases</span><strong>{len(self.database_stats)}</strong></div>
                </div>
                <div class="volume-card">
                    <h4>S3 Volume Metrics</h4>
                    <div class="metric"><span>Total S3 Operations</span><strong>{total_s3_ops:,}</strong></div>
                    <div class="metric"><span>Data Read (GET)</span><strong>{self._format_bytes(total_s3_bytes_out)}</strong></div>
                    <div class="metric"><span>Data Written (PUT)</span><strong>{self._format_bytes(total_s3_bytes_in)}</strong></div>
                </div>
            </div>
        </div>
"""

        # Query Types Graph
        if "query_types" in graph_data:
            html += f"""
        <div class="card">
            <h2>Query Types Distribution</h2>
            <div class="graph">
                <img src="data:image/png;base64,{graph_data["query_types"]}" alt="Query Types">
            </div>
        </div>
"""

        # Daily Activity Graph
        if "daily_activity" in graph_data:
            html += f"""
        <div class="card">
            <h2>Daily Activity</h2>
            <div class="graph">
                <img src="data:image/png;base64,{graph_data["daily_activity"]}" alt="Daily Activity">
            </div>
        </div>
"""

        # Workgroup Analysis
        html += """
        <div class="card">
            <h2>Workgroup Analysis</h2>
"""
        if "workgroup_queries" in graph_data:
            html += f"""
            <div class="graph">
                <img src="data:image/png;base64,{graph_data["workgroup_queries"]}" alt="Workgroup Queries">
            </div>
"""

        # Workgroup table
        sorted_wgs = sorted(
            self.workgroup_stats.items(), key=lambda x: -x[1]["query_count"]
        )[:10]
        html += """
            <table>
                <tr><th>Workgroup</th><th>Queries</th><th>Users</th><th>Data Scanned</th></tr>
"""
        for wg, stats in sorted_wgs:
            data_scanned_str = self._format_bytes(stats["total_data_scanned"])
            html += f"""
                <tr>
                    <td>{wg}</td>
                    <td>{stats["query_count"]:,}</td>
                    <td>{len(stats["users"])}</td>
                    <td>{data_scanned_str}</td>
                </tr>
"""
        html += """
            </table>
        </div>
"""

        # Data Scanned Graph
        if "data_scanned" in graph_data:
            html += f"""
        <div class="card">
            <h2>Data Scanned by Workgroup</h2>
            <div class="graph">
                <img src="data:image/png;base64,{graph_data["data_scanned"]}" alt="Data Scanned">
            </div>
        </div>
"""

        # Top Users
        html += """
        <div class="card">
            <h2>Top Users</h2>
"""
        if "top_users" in graph_data:
            html += f"""
            <div class="graph">
                <img src="data:image/png;base64,{graph_data["top_users"]}" alt="Top Users">
            </div>
"""

        sorted_users = sorted(
            self.user_stats.items(), key=lambda x: -x[1]["query_count"]
        )[:10]
        html += """
            <table>
                <tr><th>User</th><th>Queries</th><th>Workgroups</th><th>Databases</th></tr>
"""
        for user, stats in sorted_users:
            html += f"""
                <tr>
                    <td>{user}</td>
                    <td>{stats["query_count"]:,}</td>
                    <td>{len(stats["workgroups"])}</td>
                    <td>{len(stats["databases"])}</td>
                </tr>
"""
        html += """
            </table>
        </div>
"""

        # S3 Operations
        if self.s3_bucket_stats:
            html += """
        <div class="card">
            <h2>S3 Bucket Operations</h2>
"""
            if "s3_operations" in graph_data:
                html += f"""
            <div class="graph">
                <img src="data:image/png;base64,{graph_data["s3_operations"]}" alt="S3 Operations">
            </div>
"""

            sorted_buckets = sorted(
                self.s3_bucket_stats.items(),
                key=lambda x: -(
                    x[1]["get_count"] + x[1]["put_count"] + x[1]["list_count"]
                ),
            )[:10]
            html += """
            <table>
                <tr><th>Bucket</th><th>GET</th><th>PUT</th><th>LIST</th><th>Data Read</th><th>Data Written</th><th>Users</th></tr>
"""
            for bucket, stats in sorted_buckets:
                bytes_out = self._format_bytes(stats["bytes_out"])
                bytes_in = self._format_bytes(stats["bytes_in"])
                html += f"""
                <tr>
                    <td>{bucket}</td>
                    <td>{stats["get_count"]:,}</td>
                    <td>{stats["put_count"]:,}</td>
                    <td>{stats["list_count"]:,}</td>
                    <td>{bytes_out}</td>
                    <td>{bytes_in}</td>
                    <td>{len(stats["users"])}</td>
                </tr>
"""
            html += """
            </table>
        </div>
"""

        # SQL Dialect Features
        if self.sql_features:
            html += """
        <div class="card">
            <h2>SQL Dialect Features</h2>
            <p style="color: #666; margin-bottom: 15px;">Advanced SQL features detected in queries. Review for compatibility when migrating to other platforms.</p>
"""
            if "sql_features" in graph_data:
                html += f"""
            <div class="graph">
                <img src="data:image/png;base64,{graph_data["sql_features"]}" alt="SQL Features">
            </div>
"""
            sorted_features = sorted(self.sql_features.items(), key=lambda x: -x[1])[:15]
            html += """
            <table>
                <tr><th>Feature</th><th>Occurrences</th><th>Notes</th></tr>
"""
            # Add notes for features that may need attention
            feature_notes = {
                "CTE": "Common Table Expressions - widely supported",
                "Window Functions": "Check specific function compatibility",
                "UNNEST": "Array expansion - verify syntax compatibility",
                "Lambda Expressions": "May require syntax adjustment",
                "Array/Map Functions": "Verify function availability",
                "CROSS JOIN UNNEST": "Common pattern - verify support",
                "GROUPING SETS": "Advanced aggregation - check support",
                "CUBE": "Advanced aggregation - check support",
                "ROLLUP": "Advanced aggregation - check support",
                "TABLESAMPLE": "Table sampling - may not be supported",
                "LATERAL": "Lateral joins - verify support",
            }
            for feature, count in sorted_features:
                note = feature_notes.get(feature, "Review for compatibility")
                if feature.startswith("Trino:"):
                    note = "Trino/Presto specific - verify equivalent"
                html += f"""
                <tr>
                    <td><strong>{feature}</strong></td>
                    <td>{count:,}</td>
                    <td style="color: #666; font-size: 0.9em;">{note}</td>
                </tr>
"""
            html += """
            </table>
        </div>
"""

        # Query Status & Failed Queries
        if self.query_status_counts:
            failed_count = self.query_status_counts.get("FAILED", 0)
            succeeded_count = self.query_status_counts.get("SUCCEEDED", 0)
            total_status = sum(self.query_status_counts.values())
            failure_rate = (failed_count / total_status * 100) if total_status > 0 else 0

            html += f"""
        <div class="card">
            <h2>Query Status & Failed Queries</h2>
            <div class="stats-grid" style="margin-bottom: 20px;">
                <div class="stat-box" style="background: linear-gradient(135deg, #28a745, #218838);">
                    <div class="value">{succeeded_count:,}</div>
                    <div class="label">Succeeded</div>
                </div>
                <div class="stat-box" style="background: linear-gradient(135deg, #dc3545, #c82333);">
                    <div class="value">{failed_count:,}</div>
                    <div class="label">Failed</div>
                </div>
                <div class="stat-box">
                    <div class="value">{failure_rate:.1f}%</div>
                    <div class="label">Failure Rate</div>
                </div>
            </div>
"""
            if "query_status" in graph_data:
                html += f"""
            <div class="graph">
                <img src="data:image/png;base64,{graph_data["query_status"]}" alt="Query Status">
            </div>
"""
            if self.error_types:
                html += """
            <h3 style="margin-top: 20px;">Error Type Breakdown</h3>
            <table>
                <tr><th>Error Type</th><th>Count</th><th>Example</th></tr>
"""
                for error_type, count in sorted(self.error_types.items(), key=lambda x: -x[1]):
                    example = ""
                    if error_type in self.error_examples and self.error_examples[error_type]:
                        example = self.error_examples[error_type][0][:100]
                        if len(self.error_examples[error_type][0]) > 100:
                            example += "..."
                    html += f"""
                <tr>
                    <td><strong>{error_type}</strong></td>
                    <td>{count:,}</td>
                    <td style="font-family: monospace; font-size: 0.85em; color: #666;">{example}</td>
                </tr>
"""
                html += """
            </table>
"""
            html += """
        </div>
"""

        # Query Execution Time Distribution
        if self.execution_time_buckets:
            html += """
        <div class="card">
            <h2>Query Execution Time Distribution</h2>
"""
            if "execution_time" in graph_data:
                html += f"""
            <div class="graph">
                <img src="data:image/png;base64,{graph_data["execution_time"]}" alt="Execution Time">
            </div>
"""
            # Calculate statistics
            if self.execution_times:
                avg_ms = sum(self.execution_times) / len(self.execution_times)
                min_ms = min(self.execution_times)
                max_ms = max(self.execution_times)
                sorted_times = sorted(self.execution_times)
                p50_ms = sorted_times[len(sorted_times) // 2]
                p95_idx = int(len(sorted_times) * 0.95)
                p95_ms = sorted_times[p95_idx] if p95_idx < len(sorted_times) else max_ms

                html += f"""
            <div class="stats-grid" style="margin-top: 20px;">
                <div class="stat-box" style="background: linear-gradient(135deg, #28a745, #218838);">
                    <div class="value">{min_ms/1000:.1f}s</div>
                    <div class="label">Minimum</div>
                </div>
                <div class="stat-box" style="background: linear-gradient(135deg, #17a2b8, #138496);">
                    <div class="value">{avg_ms/1000:.1f}s</div>
                    <div class="label">Average</div>
                </div>
                <div class="stat-box" style="background: linear-gradient(135deg, #ffc107, #e0a800);">
                    <div class="value">{p50_ms/1000:.1f}s</div>
                    <div class="label">Median (P50)</div>
                </div>
                <div class="stat-box" style="background: linear-gradient(135deg, #ff9800, #f57c00);">
                    <div class="value">{p95_ms/1000:.1f}s</div>
                    <div class="label">P95</div>
                </div>
                <div class="stat-box" style="background: linear-gradient(135deg, #dc3545, #c82333);">
                    <div class="value">{max_ms/1000:.1f}s</div>
                    <div class="label">Maximum</div>
                </div>
            </div>
"""
            # Bucket breakdown table
            bucket_order = [
                "< 1 second",
                "1-5 seconds",
                "5-30 seconds",
                "30s - 1 minute",
                "1-5 minutes",
                "5-10 minutes",
                "> 10 minutes",
            ]
            total_timed = sum(self.execution_time_buckets.values())
            html += """
            <table style="margin-top: 20px;">
                <tr><th>Time Bucket</th><th>Count</th><th>Percentage</th></tr>
"""
            for bucket in bucket_order:
                count = self.execution_time_buckets.get(bucket, 0)
                pct = (count / total_timed * 100) if total_timed > 0 else 0
                html += f"""
                <tr>
                    <td>{bucket}</td>
                    <td>{count:,}</td>
                    <td>{pct:.1f}%</td>
                </tr>
"""
            html += """
            </table>
        </div>
"""

        # Query Patterns (all, sorted by frequency)
        html += f"""
        <div class="card">
            <h2>Query Patterns (by frequency)</h2>
            <p style="color: #666;">{len(self.query_patterns)} unique patterns detected</p>
            <div style="max-height: 500px; overflow-y: auto;">
"""
        sorted_patterns = sorted(
            self.query_patterns.items(), key=lambda x: -x[1]["count"]
        )
        for i, (pattern_hash, pattern) in enumerate(sorted_patterns, 1):
            example = pattern["examples"][0] if pattern["examples"] else "No example"
            html += f"""
            <div style="margin-bottom: 15px; padding: 12px; background: #f9f9f9; border-radius: 5px; border-left: 3px solid #007bff;">
                <strong>#{i}</strong> - Executions: {pattern["count"]:,} | Users: {len(pattern["users"])}
                <div class="query-example" style="white-space: pre-wrap; word-break: break-word; margin-top: 8px;">{example}</div>
            </div>
"""
        html += """
            </div>
        </div>
"""

        # === MIGRATION READINESS ANALYSIS SECTION ===
        # Calculate migration readiness score
        readiness = self._calculate_migration_readiness_score()

        # Readiness level colors (higher = better = greener)
        readiness_colors = {
            "HIGH": "#28a745",
            "GOOD": "#5cb85c",
            "MODERATE": "#ffc107",
            "LOW": "#dc3545",
        }
        readiness_color = readiness_colors.get(readiness["level"], "#6c757d")

        html += f"""
        <div class="card" style="border-left: 5px solid {readiness_color};">
            <h2>Migration Readiness Analysis</h2>
            <div style="display: flex; align-items: center; margin-bottom: 20px;">
                <div style="font-size: 48px; font-weight: bold; color: {readiness_color}; margin-right: 20px;">
                    {readiness["score"]}
                </div>
                <div>
                    <div style="font-size: 24px; font-weight: bold; color: {readiness_color};">
                        {readiness["level"]} READINESS
                    </div>
                    <div style="color: #666;">Migration Readiness Score (0-100, higher is better)</div>
                </div>
            </div>
"""

        if readiness["considerations"]:
            html += """
            <h3>Considerations</h3>
            <ul style="margin-bottom: 20px;">
"""
            for detail in readiness["considerations"]:
                html += f"                <li>{detail}</li>\n"
            html += """
            </ul>
"""

        html += """
        </div>

        <div class="card">
            <h2>Query Complexity Analysis</h2>
"""

        # Query complexity stats
        html += f"""
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px;">
                <div class="metric">
                    <div class="value">{len(self.high_complexity_queries)}</div>
                    <div class="label">High Complexity Queries (3+ JOINs)</div>
                </div>
                <div class="metric">
                    <div class="value">{self.queries_with_multiple_joins}</div>
                    <div class="label">Queries with Multiple JOINs</div>
                </div>
                <div class="metric">
                    <div class="value">{self.cte_usage_count}</div>
                    <div class="label">Queries Using CTEs</div>
                </div>
                <div class="metric">
                    <div class="value">{self.full_table_scans}</div>
                    <div class="label">Potential Full Table Scans</div>
                </div>
            </div>
"""

        # JOIN type breakdown
        if self.join_type_counts:
            html += """
            <h3>JOIN Types Used</h3>
            <table>
                <tr><th>JOIN Type</th><th>Count</th></tr>
"""
            for join_type, count in sorted(self.join_type_counts.items(), key=lambda x: -x[1]):
                html += f"""
                <tr><td>{join_type}</td><td>{count:,}</td></tr>
"""
            html += """
            </table>
"""

        # High complexity query examples
        if self.high_complexity_queries:
            html += f"""
            <h3>High Complexity Queries ({len(self.high_complexity_queries)} total)</h3>
            <div style="max-height: 500px; overflow-y: auto;">
"""
            for i, q in enumerate(self.high_complexity_queries[:10], 1):
                join_types_str = ", ".join(q["join_types"][:5]) if q["join_types"] else "N/A"
                preview = q["query_preview"]
                html += f"""
                <div style="margin-bottom: 15px; padding: 10px; background: #fff3cd; border-radius: 5px;">
                    <strong>#{i}</strong> - JOINs: {q["join_count"]}, CTEs: {q["cte_count"]}, Subqueries: {q["subquery_depth"]}
                    <br><small>JOIN types: {join_types_str}</small>
                    <div class="query-example" style="white-space: pre-wrap; word-break: break-word;">{preview}</div>
                </div>
"""
            if len(self.high_complexity_queries) > 10:
                html += f"""
                <p><em>... and {len(self.high_complexity_queries) - 10} more high complexity queries</em></p>
"""
            html += """
            </div>
"""

        html += """
        </div>

        <div class="card">
            <h2>DDL Operations Analysis</h2>
"""

        total_ddl = sum(self.ddl_by_type.values())
        if total_ddl > 0:
            html += f"""
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px;">
                <div class="metric">
                    <div class="value">{total_ddl}</div>
                    <div class="label">Total DDL Operations</div>
                </div>
                <div class="metric">
                    <div class="value" style="color: #dc3545;">{self.ddl_by_type.get("DROP", 0)}</div>
                    <div class="label">DROP Operations</div>
                </div>
                <div class="metric">
                    <div class="value">{self.ddl_by_type.get("CREATE", 0)}</div>
                    <div class="label">CREATE Operations</div>
                </div>
                <div class="metric">
                    <div class="value">{self.ddl_by_type.get("ALTER", 0)}</div>
                    <div class="label">ALTER Operations</div>
                </div>
            </div>
"""

            # DDL Queries
            if self.ddl_operations:
                html += f"""
            <h3>DDL Queries ({len(self.ddl_operations)} total)</h3>
            <div style="max-height: 400px; overflow-y: auto;">
"""
                # Group by type
                for ddl_type in ["DROP", "CREATE", "ALTER", "TRUNCATE"]:
                    type_ops = [op for op in self.ddl_operations if op["type"] == ddl_type]
                    if type_ops:
                        color = "#dc3545" if ddl_type == "DROP" else "#28a745" if ddl_type == "CREATE" else "#ffc107"
                        html += f'<h4 style="color: {color};">{ddl_type} ({len(type_ops)})</h4>'
                        for op in type_ops[:10]:  # Show up to 10 per type
                            html += f"""
                <div style="margin-bottom: 10px; padding: 10px; background: #f8f9fa; border-left: 3px solid {color}; border-radius: 3px;">
                    <small style="color: #666;">User: {op["user"][:30]}</small>
                    <div class="query-example" style="white-space: pre-wrap; word-break: break-word; margin-top: 5px;">{op["query"]}</div>
                </div>
"""
                        if len(type_ops) > 10:
                            html += f'<p><em>... and {len(type_ops) - 10} more {ddl_type} operations</em></p>'
                html += """
            </div>
"""

            # DDL by user
            if self.ddl_by_user:
                html += """
            <h3>DDL by User</h3>
            <table>
                <tr><th>User</th><th>CREATE</th><th>DROP</th><th>ALTER</th><th>Total</th></tr>
"""
                for user, ops in sorted(self.ddl_by_user.items(), key=lambda x: -sum(x[1].values()))[:10]:
                    total_user_ddl = sum(ops.values())
                    html += f"""
                <tr>
                    <td>{user[:40]}</td>
                    <td>{ops.get("CREATE", 0)}</td>
                    <td>{ops.get("DROP", 0)}</td>
                    <td>{ops.get("ALTER", 0)}</td>
                    <td>{total_user_ddl}</td>
                </tr>
"""
                html += """
            </table>
"""
        else:
            html += """
            <p>No DDL operations detected in the analyzed period.</p>
"""

        html += """
        </div>

        <div class="card">
            <h2>Long-Running Query Analysis</h2>
"""

        total_long = len(self.long_running_queries) + len(self.very_long_queries)
        html += f"""
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 20px;">
                <div class="metric">
                    <div class="value">{len(self.long_running_queries)}</div>
                    <div class="label">Queries 10-30 minutes</div>
                </div>
                <div class="metric">
                    <div class="value" style="color: #fd7e14;">{len(self.very_long_queries)}</div>
                    <div class="label">Queries 30+ minutes</div>
                </div>
                <div class="metric">
                    <div class="value" style="color: #dc3545;">{self.queries_over_1hr}</div>
                    <div class="label">Queries 1+ hour</div>
                </div>
            </div>
"""

        if self.very_long_queries:
            html += """
            <h3>Very Long Queries (30+ minutes)</h3>
            <div style="max-height: 400px; overflow-y: auto;">
"""
            for i, q in enumerate(sorted(self.very_long_queries, key=lambda x: -x["execution_time_ms"])[:5], 1):
                preview = q["query_preview"]
                html += f"""
                <div style="margin-bottom: 10px; padding: 10px; background: #f8d7da; border-radius: 5px;">
                    <strong>#{i}</strong> - Duration: {q["execution_time_min"]} minutes | User: {q["user"][:30]}
                    <div class="query-example" style="white-space: pre-wrap; word-break: break-word;">{preview}</div>
                </div>
"""
            html += """
            </div>
"""

        html += """
        </div>

        <div class="card">
            <h2>Concurrency & Performance</h2>
"""

        html += f"""
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 20px;">
                <div class="metric">
                    <div class="value">{self.peak_concurrency}</div>
                    <div class="label">Peak Concurrent Queries (per minute)</div>
                </div>
                <div class="metric">
                    <div class="value">{self.queries_using_partition_filter}</div>
                    <div class="label">Queries Using Partition Filters</div>
                </div>
                <div class="metric">
                    <div class="value">{self.queries_missing_partition_filter}</div>
                    <div class="label">Queries Missing Partition Filters</div>
                </div>
            </div>
"""

        # Data scan stats
        if self.data_scanned_per_query:
            avg_scan = sum(self.data_scanned_per_query) / len(self.data_scanned_per_query)
            max_scan = max(self.data_scanned_per_query)
            total_scan = sum(self.data_scanned_per_query)
            html += f"""
            <h3>Data Scan Statistics</h3>
            <p><strong>Average per query:</strong> {self._format_bytes(int(avg_scan))}</p>
            <p><strong>Maximum single query:</strong> {self._format_bytes(max_scan)}</p>
            <p><strong>Total scanned:</strong> {self._format_bytes(total_scan)}</p>
"""

        # Top data consumers by user
        if self.data_scanned_by_user:
            html += """
            <h3>Top Data Consumers by User</h3>
            <table>
                <tr><th>User</th><th>Data Scanned</th></tr>
"""
            for user, scanned in sorted(self.data_scanned_by_user.items(), key=lambda x: -x[1])[:10]:
                html += f"""
                <tr><td>{user[:40]}</td><td>{self._format_bytes(scanned)}</td></tr>
"""
            html += """
            </table>
"""

        html += """
        </div>

        <div class="card">
            <h2>SQL Compatibility Flags</h2>
            <p>Features that may require attention during migration:</p>
"""

        if self.migration_flags:
            html += """
            <table>
                <tr><th>Feature</th><th>Occurrences</th><th style="width: 60%;">Example</th></tr>
"""
            for flag, examples in sorted(self.migration_flags.items(), key=lambda x: -len(x[1])):
                example_preview = examples[0]["query_preview"][:300] if examples else "N/A"
                html += f"""
                <tr>
                    <td><strong>{flag}</strong></td>
                    <td>{len(examples)}</td>
                    <td class="query-example" style="font-size: 11px; white-space: pre-wrap; word-break: break-word;">{example_preview}</td>
                </tr>
"""
            html += """
            </table>
"""
        else:
            html += """
            <p style="color: #28a745;">No compatibility flags detected - queries appear migration-ready.</p>
"""

        # Object size analysis
        if self.object_sizes:
            avg_size = sum(self.object_sizes) / len(self.object_sizes)
            small_pct = self.small_file_count / len(self.object_sizes) * 100 if self.object_sizes else 0

            size_warning = ""
            if avg_size < 10 * 1024 * 1024:  # < 10MB
                size_warning = "style='color: #fd7e14;'"
            elif avg_size < 50 * 1024 * 1024:  # < 50MB
                size_warning = "style='color: #ffc107;'"

            html += f"""
            <h3>Object/File Size Analysis</h3>
            <p {size_warning}><strong>Average object size:</strong> {self._format_bytes(int(avg_size))} (recommend 100MB+ for Spark)</p>
            <p><strong>Small files (&lt;10MB):</strong> {self.small_file_count:,} ({small_pct:.1f}%)</p>
            <p><strong>Total objects analyzed:</strong> {len(self.object_sizes):,}</p>
"""

        html += """
        </div>

        <div class="card">
            <h2>Migration Recommendations</h2>
            <ul>
"""

        # Generate recommendations based on analysis
        recommendations = []

        if len(self.high_complexity_queries) > 0:
            recommendations.append(f"Review {len(self.high_complexity_queries)} high-complexity queries with 3+ JOINs - these may cause query optimizer issues")

        if self.ddl_by_type.get("DROP", 0) > 5:
            drop_count = self.ddl_by_type.get("DROP", 0)
            recommendations.append(f"Review DDL patterns: {drop_count} DROP operations detected - consider implementing DDL governance")

        if self.queries_over_1hr > 0:
            recommendations.append(f"Investigate {self.queries_over_1hr} queries running over 1 hour - verify query cancellation capability in target platform")

        if self.full_table_scans > 10:
            recommendations.append(f"Optimize {self.full_table_scans} potential full table scans - verify scan limits in target platform")

        if self.object_sizes and sum(self.object_sizes) / len(self.object_sizes) < 50 * 1024 * 1024:
            recommendations.append("Consider file compaction - small files cause API throttling and performance issues")

        if self.cte_usage_count > 50:
            recommendations.append(f"Review {self.cte_usage_count} queries using CTEs - these create temp result sets that stress Spark optimizer")

        for flag, examples in self.migration_flags.items():
            if flag == "GEOSPATIAL" and len(examples) > 0:
                recommendations.append(f"Validate {len(examples)} geospatial queries - check Spark SQL compatibility")
            if flag == "FEDERATED_QUERY" and len(examples) > 0:
                recommendations.append(f"Plan migration for {len(examples)} federated queries - may require different approach in target platform")

        if not recommendations:
            recommendations.append("No significant migration considerations detected - proceed with standard migration approach")

        for rec in recommendations:
            html += f"                <li>{rec}</li>\n"

        html += """
            </ul>
        </div>
"""

        # Footer
        html += f"""
        <div class="footer">
            <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p>Athena Usage Analyser - Migration Readiness Assessment</p>
        </div>
    </div>
</body>
</html>
"""

        return html


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Athena usage exports and generate reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 analyse_exports.py ./exports/
  python3 analyse_exports.py ./exports/ --output report.txt
  python3 analyse_exports.py ./exports/ --html report.html
  python3 analyse_exports.py ./exports/ --graphs ./graphs/
  python3 analyse_exports.py ./exports/ --no-open
        """,
    )
    parser.add_argument(
        "exports_path", help="Path to exports folder or single zip file"
    )
    parser.add_argument(
        "--output", "-o", help="Output path for text report (instead of HTML)"
    )
    parser.add_argument(
        "--html", help="Custom path for HTML report (default: auto-generated)"
    )
    parser.add_argument("--graphs", "-g", help="Directory to save graph images")
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress console output"
    )
    parser.add_argument(
        "--no-open", action="store_true", help="Do not auto-open the HTML report"
    )

    args = parser.parse_args()

    # Validate path
    exports_path = Path(args.exports_path)
    if not exports_path.exists():
        print(f"Error: Path does not exist: {exports_path}")
        sys.exit(1)

    # Create analyser and load data
    analyser = AthenaExportAnalyser(str(exports_path))
    file_count = analyser.load_exports()

    if file_count == 0:
        print("No export files found to analyze.")
        sys.exit(1)

    # Determine output mode
    html_path = None

    if args.output:
        # Text report mode (explicitly requested)
        report = analyser.generate_report(args.output)
        if not args.quiet:
            print("\n" + report)
    else:
        # HTML report mode (default)
        if args.html:
            html_path = args.html
        else:
            # Auto-generate HTML filename
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            html_path = f"athena-usage-report-{timestamp}.html"

        analyser.generate_html_report(html_path)

        # Auto-open the HTML file
        if not args.no_open:
            abs_path = os.path.abspath(html_path)
            print(f"Opening report in browser: {abs_path}")
            try:
                # Use 'open' on macOS for better browser handling
                if sys.platform == "darwin":
                    subprocess.run(["open", abs_path], check=True)
                elif sys.platform == "win32":
                    os.startfile(abs_path)
                else:
                    webbrowser.open(f"file://{abs_path}")
            except Exception as e:
                print(f"Could not auto-open file: {e}")
                print(f"Please open manually: {abs_path}")

    # Generate graphs if requested
    if args.graphs:
        analyser.generate_graphs(args.graphs)

    print("\nAnalysis complete!")


if __name__ == "__main__":
    main()
