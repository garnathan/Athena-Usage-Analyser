"""Athena Usage Analyser Lambda."""

import gzip
import hashlib
import io
import json
import logging
import os
import re
import time
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict

import boto3

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients (for local/single-account use)
s3_client = boto3.client("s3")
cloudtrail_client = boto3.client("cloudtrail")
athena_client = boto3.client("athena")
logs_client = boto3.client("logs")
sts_client = boto3.client("sts")

# Configuration from environment variables
OUTPUT_BUCKET = os.environ.get("OUTPUT_BUCKET", "")
CLOUDTRAIL_BUCKET = os.environ.get("CLOUDTRAIL_BUCKET", "")
LOOKBACK_MINUTES = int(os.environ.get("LOOKBACK_MINUTES", "60"))
LOG_GROUP_NAME = os.environ.get("LOG_GROUP_NAME", "/athena-usage-analyser/events")
ATHENA_WORKGROUPS = os.environ.get("ATHENA_WORKGROUPS", "*")
S3_BUCKETS_TO_MONITOR = os.environ.get("S3_BUCKETS_TO_MONITOR", "*")
STACK_NAME = os.environ.get("STACK_NAME", "athena-analyser")
MODE = os.environ.get("MODE", "SCHEDULED")  # 'SCHEDULED' or 'LOOKBACK'
ANALYSIS_MODE = os.environ.get("ANALYSIS_MODE", "single")  # 'single' or 'multi'
MONITORED_ACCOUNT_IDS = os.environ.get("MONITORED_ACCOUNT_IDS", "")
CROSS_ACCOUNT_EXTERNAL_ID = os.environ.get("CROSS_ACCOUNT_EXTERNAL_ID", "")
MULTI_ACCOUNT_METHOD = os.environ.get(
    "MULTI_ACCOUNT_METHOD", "manual"
)  # 'manual' or 'org'
ORGANIZATION_ID = os.environ.get("ORGANIZATION_ID", "")
ORG_TRAIL_BUCKET = os.environ.get("ORG_TRAIL_BUCKET", "")

# Lookback mode goes back 90 days (CloudTrail API limit)
LOOKBACK_MODE_DAYS = 90

# Parse monitored resources
MONITORED_WORKGROUPS = set(w.strip() for w in ATHENA_WORKGROUPS.split(",") if w.strip())
MONITORED_S3_BUCKETS = set(
    b.strip() for b in S3_BUCKETS_TO_MONITOR.split(",") if b.strip()
)

# Parse monitored accounts
MONITORED_ACCOUNTS = [a.strip() for a in MONITORED_ACCOUNT_IDS.split(",") if a.strip()]

# Cached values (populated on first use)
_cached_account_id = None
_cached_region = None


def _get_account_id():
    """Get the current AWS account ID (cached)."""
    global _cached_account_id
    if _cached_account_id is None:
        _cached_account_id = sts_client.get_caller_identity()["Account"]
    return _cached_account_id


def _get_region():
    """Get the current AWS region (cached)."""
    global _cached_region
    if _cached_region is None:
        _cached_region = boto3.session.Session().region_name
    return _cached_region


def discover_org_accounts():
    """Discover active member accounts via AWS Organizations API."""
    org_client = boto3.client("organizations")
    accounts = []
    try:
        local_account_id = _get_account_id()
        paginator = org_client.get_paginator("list_accounts")
        for page in paginator.paginate():
            for acct in page.get("Accounts", []):
                if acct["Status"] == "ACTIVE" and acct["Id"] != local_account_id:
                    accounts.append(acct["Id"])
        logger.info(
            f"Discovered {len(accounts)} active member accounts via Organizations"
        )
    except Exception as e:
        logger.error(f"Failed to discover org accounts: {str(e)}")
    return accounts


# Athena-related CloudTrail event names
ATHENA_EVENTS = frozenset([
    "StartQueryExecution",
    "StopQueryExecution",
    "GetQueryExecution",
    "GetQueryResults",
    "CreateNamedQuery",
    "DeleteNamedQuery",
    "GetNamedQuery",
    "ListNamedQueries",
    "BatchGetNamedQuery",
    "CreateWorkGroup",
    "DeleteWorkGroup",
    "GetWorkGroup",
    "ListWorkGroups",
    "UpdateWorkGroup",
    "CreateDataCatalog",
    "DeleteDataCatalog",
    "GetDataCatalog",
    "ListDataCatalogs",
    "GetDatabase",
    "ListDatabases",
    "GetTableMetadata",
    "ListTableMetadata",
    "CreatePreparedStatement",
    "DeletePreparedStatement",
    "GetPreparedStatement",
    "ListPreparedStatements",
    "StartSession",
    "TerminateSession",
    "GetSession",
    "ListSessions",
    "StartCalculationExecution",
    "StopCalculationExecution",
    "GetCalculationExecution",
    "ListCalculationExecutions",
])

S3_EVENTS = frozenset(["GetObject", "PutObject", "ListObjects", "ListObjectsV2", "HeadObject"])


# ---------------------------------------------------------------------------
# Cross-account helpers
# ---------------------------------------------------------------------------


def get_cross_account_clients(account_id):
    """Assume role in a monitored account and return boto3 clients."""
    role_arn = f"arn:aws:iam::{account_id}:role/AthenaUsageAnalyserReadRole"
    logger.info(f"Assuming role {role_arn} for account {account_id}")
    try:
        assume_params = {
            "RoleArn": role_arn,
            "RoleSessionName": f"AthenaAnalyser-{account_id}",
            "DurationSeconds": 3600,
        }
        if CROSS_ACCOUNT_EXTERNAL_ID:
            assume_params["ExternalId"] = CROSS_ACCOUNT_EXTERNAL_ID
        response = sts_client.assume_role(**assume_params)
        creds = response["Credentials"]
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        return {
            "cloudtrail": session.client("cloudtrail"),
            "athena": session.client("athena"),
            "s3": session.client("s3"),
            "account_id": account_id,
        }
    except Exception as e:
        logger.error(f"Failed to assume role for account {account_id}: {str(e)}")
        return None


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------


def log_configuration_summary(run_mode, start_time, end_time):
    logger.info("=" * 60)
    logger.info("CONFIGURATION")
    logger.info("=" * 60)
    logger.info(f"Mode: {run_mode}")
    logger.info(f"Analysis Mode: {ANALYSIS_MODE}")
    if ANALYSIS_MODE == "multi":
        logger.info(f"Multi-Account Method: {MULTI_ACCOUNT_METHOD}")
        if MULTI_ACCOUNT_METHOD == "org":
            logger.info(f"Organization ID: {ORGANIZATION_ID}")
            logger.info(f"Org Trail Bucket: {ORG_TRAIL_BUCKET or 'NOT CONFIGURED'}")
        else:
            logger.info(f"Monitored Accounts: {', '.join(MONITORED_ACCOUNTS)}")
    logger.info(f"Time Range: {start_time} to {end_time}")
    if "*" in MONITORED_WORKGROUPS:
        logger.info("Monitored Workgroups: ALL WORKGROUPS (*)")
    else:
        logger.info(f"Monitored Workgroups: {', '.join(sorted(MONITORED_WORKGROUPS))}")
    if "*" in MONITORED_S3_BUCKETS:
        logger.info("Monitored S3 Buckets: AUTO-DETECT")
    else:
        logger.info(f"Monitored S3 Buckets: {', '.join(sorted(MONITORED_S3_BUCKETS))}")
    if CLOUDTRAIL_BUCKET:
        logger.info(f"CloudTrail Bucket: {CLOUDTRAIL_BUCKET}")
    else:
        logger.info("CloudTrail Bucket: NOT CONFIGURED")
    logger.info("=" * 60)


def log_no_athena_events_warning(start_time, end_time, skipped_workgroups):
    logger.warning("!" * 65)
    logger.warning("WARNING: NO ATHENA EVENTS FOUND")
    logger.warning("!" * 65)
    if "*" in MONITORED_WORKGROUPS:
        logger.warning("Monitored Workgroups: ALL WORKGROUPS (*)")
    else:
        logger.warning(
            f"Monitored Workgroups: {', '.join(sorted(MONITORED_WORKGROUPS))}"
        )
    logger.warning(f"Time Range: {start_time} to {end_time}")
    if skipped_workgroups:
        logger.warning(
            f"Workgroups seen but filtered out: {', '.join(sorted(skipped_workgroups))}"
        )
    logger.warning("")
    logger.warning("Possible causes:")
    logger.warning("  - No Athena queries were run during this time period")
    logger.warning("  - The specified workgroups do not exist in this account")
    logger.warning("  - CloudTrail is not enabled or not logging Athena events")
    logger.warning("  - Workgroup names are case-sensitive - verify spelling")
    logger.warning("")
    logger.warning("To verify workgroups exist, run:")
    logger.warning("  aws athena list-work-groups --region <region>")
    logger.warning("!" * 65)


def log_no_s3_events_warning(start_time, end_time, skipped_buckets):
    logger.warning("!" * 65)
    logger.warning("WARNING: NO S3 EVENTS FOUND")
    logger.warning("!" * 65)
    if "*" in MONITORED_S3_BUCKETS:
        logger.warning("Monitored S3 Buckets: AUTO-DETECT mode")
        logger.warning("  (patterns: athena, query-results, datalake, etc.)")
    else:
        logger.warning(
            f"Monitored S3 Buckets: {', '.join(sorted(MONITORED_S3_BUCKETS))}"
        )
    logger.warning(f"Time Range: {start_time} to {end_time}")
    if skipped_buckets:
        logger.warning(
            f"Buckets seen but filtered out: {', '.join(sorted(list(skipped_buckets)[:10]))}"
        )
        if len(skipped_buckets) > 10:
            logger.warning(f"  ... and {len(skipped_buckets) - 10} more")
    logger.warning("")
    logger.warning("Possible causes:")
    logger.warning("  - No S3 operations occurred during this time period")
    logger.warning("  - The specified bucket names do not exist")
    logger.warning("  - CloudTrail data events are not enabled for S3")
    logger.warning("  - In AUTO-DETECT mode, no buckets matched the expected patterns")
    logger.warning("!" * 65)


def log_success_summary(
    athena_count, s3_count, users, workgroups, export_location, queries_fetched=0
):
    logger.info("=" * 60)
    logger.info("SUCCESS: ANALYSIS COMPLETE")
    logger.info("=" * 60)
    logger.info(f"Athena Events: {athena_count}")
    logger.info(f"Queries Fetched from Athena API: {queries_fetched}")
    logger.info(f"S3 Events: {s3_count}")
    logger.info(f"Unique Users: {users}")
    logger.info(f"Unique Workgroups: {workgroups}")
    logger.info(f"Export Location: {export_location}")
    logger.info("=" * 60)


# ---------------------------------------------------------------------------
# Core analyser
# ---------------------------------------------------------------------------


class AthenaUsageAnalyser:
    def __init__(self, account_id=None):
        self.account_id = account_id
        self.athena_events = []
        self.s3_events = []
        self.skipped_workgroups = set()
        self.skipped_buckets = set()
        self.query_execution_ids = {}
        self.fetched_queries = {}
        self.query_patterns = defaultdict(
            lambda: {
                "count": 0,
                "examples": [],
                "users": set(),
                "workgroups": set(),
                "databases": set(),
                "tables": set(),
                "total_data_scanned": 0,
                "total_execution_time_ms": 0,
            }
        )
        self.workgroup_stats = defaultdict(
            lambda: {
                "query_count": 0,
                "users": set(),
                "total_data_scanned": 0,
                "query_types": defaultdict(int),
            }
        )
        self.user_stats = defaultdict(
            lambda: {
                "query_count": 0,
                "workgroups": set(),
                "databases": set(),
                "last_activity": None,
            }
        )
        self.database_stats = defaultdict(
            lambda: {
                "query_count": 0,
                "tables": set(),
                "users": set(),
            }
        )
        self.s3_bucket_stats = defaultdict(
            lambda: {
                "get_count": 0,
                "put_count": 0,
                "list_count": 0,
                "prefixes": set(),
                "users": set(),
            }
        )
        self.hourly_query_counts = defaultdict(int)
        self.seen_event_ids = set()
        self.errors = []
        self.start_time = None
        self.end_time = None

    def should_monitor_workgroup(self, workgroup: str) -> bool:
        if "*" in MONITORED_WORKGROUPS:
            return True
        return workgroup in MONITORED_WORKGROUPS

    def should_monitor_bucket(self, bucket: str) -> bool:
        if "*" in MONITORED_S3_BUCKETS:
            return self._is_athena_related_bucket(bucket, "")
        return bucket in MONITORED_S3_BUCKETS

    def process_cloudtrail_events(
        self, start_time: datetime, end_time: datetime, ct_client=None, s3_cl=None
    ):
        self.start_time = start_time
        self.end_time = end_time
        acct_label = f" (account {self.account_id})" if self.account_id else ""
        logger.info(
            f"Processing CloudTrail events{acct_label} from {start_time} to {end_time}"
        )
        self._fetch_events_from_api(start_time, end_time, ct_client)
        # Only read from S3 for the local account (single-account mode)
        if CLOUDTRAIL_BUCKET and not self.account_id:
            self._fetch_events_from_s3(start_time, end_time, s3_cl)
        logger.info("-" * 50)
        logger.info(f"EVENT COLLECTION SUMMARY{acct_label}")
        logger.info("-" * 50)
        logger.info(
            f"CloudTrail API: {len(ATHENA_EVENTS)} Athena + {len(S3_EVENTS)} S3 event types"
        )
        logger.info(f"Athena Events Collected: {len(self.athena_events)}")
        if self.skipped_workgroups:
            logger.info(f"Athena Skipped: {', '.join(sorted(self.skipped_workgroups))}")
        logger.info(f"S3 Events Collected: {len(self.s3_events)}")
        if self.skipped_buckets:
            logger.info(
                f"S3 Events Skipped (bucket filter): {len(self.skipped_buckets)} buckets filtered"
            )
        logger.info("-" * 50)

    def _fetch_events_from_api(
        self, start_time: datetime, end_time: datetime, ct_client=None
    ):
        client = ct_client or cloudtrail_client
        try:
            paginator = client.get_paginator("lookup_events")
            for event_name in ATHENA_EVENTS:
                try:
                    for page in paginator.paginate(
                        LookupAttributes=[
                            {
                                "AttributeKey": "EventName",
                                "AttributeValue": event_name,
                            }
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        MaxResults=50,
                    ):
                        for event in page.get("Events", []):
                            self._process_event(event)
                except Exception as e:
                    logger.warning(f"Error fetching {event_name}: {str(e)}")
            for event_name in S3_EVENTS:
                try:
                    for page in paginator.paginate(
                        LookupAttributes=[
                            {
                                "AttributeKey": "EventName",
                                "AttributeValue": event_name,
                            }
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        MaxResults=50,
                    ):
                        for event in page.get("Events", []):
                            self._process_event(event)
                except Exception as e:
                    logger.warning(f"Error fetching S3 {event_name}: {str(e)}")
        except Exception as e:
            logger.error(f"CloudTrail API error: {str(e)}")
            self.errors.append(
                {
                    "source": "cloudtrail_api",
                    "error": str(e),
                    "account_id": self.account_id,
                }
            )

    def _fetch_events_from_s3(
        self, start_time: datetime, end_time: datetime, s3_cl=None
    ):
        client = s3_cl or s3_client
        try:
            account_id = _get_account_id()
            region = _get_region()
            current = start_time
            while current <= end_time:
                prefix = f"AWSLogs/{account_id}/CloudTrail/{region}/{current.strftime('%Y/%m/%d')}/"
                logger.info(f"S3 scan: {prefix}")
                paginator = client.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=CLOUDTRAIL_BUCKET, Prefix=prefix):
                    for obj in page.get("Contents", []):
                        self._process_cloudtrail_file(obj["Key"], client)
                current += timedelta(days=1)
        except Exception as e:
            logger.error(f"CloudTrail S3 error: {str(e)}")
            self.errors.append({"source": "cloudtrail_s3", "error": str(e)})

    def _process_cloudtrail_file(self, key: str, s3_cl=None):
        self._process_cloudtrail_file_from_bucket(CLOUDTRAIL_BUCKET, key, s3_cl)

    # Maximum CloudTrail file size to process (50 MB compressed)
    MAX_CT_FILE_SIZE = 50 * 1024 * 1024

    def _process_cloudtrail_file_from_bucket(self, bucket: str, key: str, s3_cl=None):
        client = s3_cl or s3_client
        try:
            response = client.get_object(Bucket=bucket, Key=key)
            content_length = response.get("ContentLength", 0)
            if content_length > self.MAX_CT_FILE_SIZE:
                logger.warning(
                    f"Skipping {key}: size {content_length} exceeds "
                    f"{self.MAX_CT_FILE_SIZE} byte limit"
                )
                return
            # Stream directly from response body into gzip decompressor
            with gzip.GzipFile(fileobj=response["Body"]) as f:
                data = json.loads(f.read())
            for record in data.get("Records", []):
                self._process_event(record)
        except Exception as e:
            logger.warning(f"Error processing {key}: {str(e)}")

    def _fetch_events_from_org_trail(
        self, account_id: str, start_time: datetime, end_time: datetime
    ):
        """Read CloudTrail events from an Organization Trail S3 bucket."""
        if not ORG_TRAIL_BUCKET or not ORGANIZATION_ID:
            logger.warning("Org trail bucket or org ID not configured, skipping")
            return
        try:
            region = _get_region()
            current = start_time
            while current <= end_time:
                prefix = (
                    f"AWSLogs/{ORGANIZATION_ID}/{account_id}/CloudTrail/"
                    f"{region}/{current.strftime('%Y/%m/%d')}/"
                )
                logger.info(f"Org trail S3 scan: {prefix}")
                paginator = s3_client.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=ORG_TRAIL_BUCKET, Prefix=prefix):
                    for obj in page.get("Contents", []):
                        self._process_cloudtrail_file_from_bucket(
                            ORG_TRAIL_BUCKET, obj["Key"]
                        )
                current += timedelta(days=1)
        except Exception as e:
            logger.error(f"Org trail S3 error for account {account_id}: {str(e)}")
            self.errors.append(
                {
                    "source": "org_trail_s3",
                    "error": str(e),
                    "account_id": account_id,
                }
            )

    def _process_event(self, event: Dict):
        try:
            if "CloudTrailEvent" in event:
                event_data = json.loads(event["CloudTrailEvent"])
            else:
                event_data = event
            # Deduplicate by CloudTrail eventID
            event_id = event_data.get("eventID", "")
            if event_id:
                if event_id in self.seen_event_ids:
                    return
                self.seen_event_ids.add(event_id)
            event_name = event_data.get("eventName", "")
            event_source = event_data.get("eventSource", "")
            if event_source == "athena.amazonaws.com" or event_name in ATHENA_EVENTS:
                self._process_athena_event(event_data)
            elif event_source == "s3.amazonaws.com" and event_name in S3_EVENTS:
                self._process_s3_event(event_data)
        except Exception as e:
            logger.warning(f"Event processing error: {str(e)}")

    def _process_athena_event(self, event: Dict):
        event_name = event.get("eventName", "")
        event_time = event.get("eventTime", "")
        user_identity = event.get("userIdentity", {})
        request_params = event.get("requestParameters", {}) or {}
        response_elements = event.get("responseElements", {}) or {}

        user_arn = user_identity.get("arn", "unknown")
        user_id = self._extract_user_id(user_arn, user_identity.get("principalId", ""))
        workgroup = request_params.get("workGroup", "primary")

        if not self.should_monitor_workgroup(workgroup):
            self.skipped_workgroups.add(workgroup)
            return

        processed_event = {
            "event_name": event_name,
            "event_time": event_time,
            "user_id": user_id,
            "user_arn": user_arn,
            "aws_region": event.get("awsRegion", ""),
            "source_ip": event.get("sourceIPAddress", ""),
            "request_parameters": request_params,
            "response_elements": response_elements,
            "error_code": event.get("errorCode"),
        }
        if self.account_id:
            processed_event["account_id"] = self.account_id
        self.athena_events.append(processed_event)

        if event_name == "StartQueryExecution":
            query_execution_id = response_elements.get("queryExecutionId", "")
            if query_execution_id:
                self.query_execution_ids[query_execution_id] = {
                    "event": processed_event,
                    "request_params": request_params,
                    "workgroup": workgroup,
                    "user_id": user_id,
                }
                # Pre-populate query data from CloudTrail requestParameters.
                # This gives us the query string even without Athena API access
                # (useful in org trail mode where cross-account roles are optional).
                # If _fetch_query_strings runs later, it overwrites with richer data.
                ct_query_string = request_params.get("queryString", "")
                if ct_query_string and query_execution_id not in self.fetched_queries:
                    self.fetched_queries[query_execution_id] = {
                        "query": ct_query_string,
                        "workgroup": workgroup,
                        "database": request_params.get("queryExecutionContext", {}).get(
                            "database", "default"
                        ),
                        "status": "",
                        "data_scanned": 0,
                        "execution_time_ms": 0,
                    }
        elif event_name == "GetQueryExecution":
            self._process_query_result(processed_event, response_elements)

        self.user_stats[user_id]["query_count"] += 1
        self.user_stats[user_id]["last_activity"] = event_time
        if event_time:
            try:
                self.hourly_query_counts[event_time[:13]] += 1
            except Exception:
                pass

    def _process_query_result(self, event: Dict, response_elements: Dict):
        query_execution = response_elements.get("queryExecution", {})
        if not query_execution:
            return
        statistics = query_execution.get("statistics", {})
        workgroup = query_execution.get("workGroup", "primary")
        data_scanned = statistics.get("dataScannedInBytes", 0)
        if data_scanned:
            self.workgroup_stats[workgroup]["total_data_scanned"] += data_scanned

    def _fetch_query_strings(self, athena_cl=None):
        if not self.query_execution_ids:
            logger.info("No query execution IDs to fetch")
            return
        client = athena_cl or athena_client
        acct_label = f" (account {self.account_id})" if self.account_id else ""
        logger.info(
            f"Fetching {len(self.query_execution_ids)} queries{acct_label} from Athena API"
        )
        execution_ids = list(self.query_execution_ids.keys())
        batch_size = 50
        for i in range(0, len(execution_ids), batch_size):
            batch = execution_ids[i : i + batch_size]
            try:
                response = client.batch_get_query_execution(QueryExecutionIds=batch)
                for qe in response.get("QueryExecutions", []):
                    qe_id = qe.get("QueryExecutionId", "")
                    query_string = qe.get("Query", "")
                    if qe_id and query_string:
                        self.fetched_queries[qe_id] = {
                            "query": query_string,
                            "workgroup": qe.get("WorkGroup", "primary"),
                            "database": qe.get("QueryExecutionContext", {}).get(
                                "Database", "default"
                            ),
                            "status": qe.get("Status", {}).get("State", ""),
                            "data_scanned": qe.get("Statistics", {}).get(
                                "DataScannedInBytes", 0
                            ),
                            "execution_time_ms": qe.get("Statistics", {}).get(
                                "EngineExecutionTimeInMillis", 0
                            ),
                        }
                for failure in response.get("UnprocessedQueryExecutionIds", []):
                    logger.warning(
                        f"Failed to fetch query {failure.get('QueryExecutionId')}: "
                        f"{failure.get('ErrorMessage')}"
                    )
            except Exception as e:
                logger.warning(f"Error fetching batch of queries: {str(e)}")
        logger.info(
            f"Successfully fetched {len(self.fetched_queries)} query strings{acct_label}"
        )

    def _process_fetched_queries(self):
        for qe_id, query_data in self.fetched_queries.items():
            event_data = self.query_execution_ids.get(qe_id, {})
            if not event_data:
                continue
            query_string = query_data["query"]
            workgroup = query_data["workgroup"]
            database = query_data["database"]
            user_id = event_data.get("user_id", "unknown")
            query_type = self._classify_query(query_string)
            tables = self._extract_tables_from_query(query_string)
            pattern_hash = self._create_query_pattern_hash(query_string)
            pattern = self.query_patterns[pattern_hash]
            pattern["count"] += 1
            pattern["users"].add(user_id)
            pattern["workgroups"].add(workgroup)
            pattern["databases"].add(database)
            pattern["tables"].update(tables)
            pattern["total_data_scanned"] += query_data.get("data_scanned", 0)
            pattern["total_execution_time_ms"] += query_data.get("execution_time_ms", 0)
            if len(pattern["examples"]) < 5:
                sanitized = self._sanitize_query(query_string)
                if sanitized not in pattern["examples"]:
                    pattern["examples"].append(sanitized)
            self.workgroup_stats[workgroup]["query_count"] += 1
            self.workgroup_stats[workgroup]["users"].add(user_id)
            self.workgroup_stats[workgroup]["query_types"][query_type] += 1
            self.workgroup_stats[workgroup]["total_data_scanned"] += query_data.get(
                "data_scanned", 0
            )
            self.database_stats[database]["query_count"] += 1
            self.database_stats[database]["tables"].update(tables)
            self.database_stats[database]["users"].add(user_id)
            self.user_stats[user_id]["workgroups"].add(workgroup)
            self.user_stats[user_id]["databases"].add(database)

    def _process_s3_event(self, event: Dict):
        request_params = event.get("requestParameters", {}) or {}
        bucket_name = request_params.get("bucketName", "")
        key = request_params.get("key", "")
        if not self.should_monitor_bucket(bucket_name):
            if bucket_name:
                self.skipped_buckets.add(bucket_name)
            return

        event_name = event.get("eventName", "")
        user_identity = event.get("userIdentity", {})
        user_id = self._extract_user_id(
            user_identity.get("arn", "unknown"),
            user_identity.get("principalId", ""),
        )

        s3_event = {
            "event_name": event_name,
            "event_time": event.get("eventTime", ""),
            "bucket": bucket_name,
            "key": key,
            "user_id": user_id,
        }
        if self.account_id:
            s3_event["account_id"] = self.account_id
        self.s3_events.append(s3_event)

        stats = self.s3_bucket_stats[bucket_name]
        if "Get" in event_name:
            stats["get_count"] += 1
        elif "Put" in event_name:
            stats["put_count"] += 1
        elif "List" in event_name:
            stats["list_count"] += 1
        if key:
            prefix = "/".join(key.split("/")[:2])
            stats["prefixes"].add(prefix)
        stats["users"].add(user_id)

    def _is_athena_related_bucket(self, bucket_name: str, key: str) -> bool:
        patterns = [
            "athena",
            "query-results",
            "datalake",
            "data-lake",
            "analytics",
            "warehouse",
            "raw",
            "processed",
            "curated",
        ]
        bucket_lower = bucket_name.lower()
        return any(p in bucket_lower for p in patterns)

    def _extract_user_id(self, user_arn: str, principal_id: str) -> str:
        if user_arn and user_arn != "unknown":
            parts = user_arn.split("/")
            if len(parts) > 1:
                return parts[-1]
            parts = user_arn.split(":")
            if len(parts) > 0:
                return parts[-1]
        return principal_id if principal_id else "unknown"

    def _classify_query(self, query: str) -> str:
        q = query.strip().upper()
        if q.startswith("SELECT"):
            return "CTAS" if " AS SELECT" in q else "SELECT"
        elif q.startswith("CREATE TABLE"):
            return "CREATE_TABLE"
        elif q.startswith("CREATE VIEW"):
            return "CREATE_VIEW"
        elif q.startswith("DROP"):
            return "DROP"
        elif q.startswith("ALTER"):
            return "ALTER"
        elif q.startswith("INSERT"):
            return "INSERT"
        elif q.startswith("SHOW"):
            return "SHOW"
        elif q.startswith("DESCRIBE"):
            return "DESCRIBE"
        elif q.startswith("MSCK"):
            return "MSCK_REPAIR"
        elif q.startswith("UNLOAD"):
            return "UNLOAD"
        return "OTHER"

    def _extract_tables_from_query(self, query: str) -> set:
        tables = set()
        patterns = [
            r"\bFROM\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)",
            r"\bJOIN\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)",
        ]
        for pattern in patterns:
            tables.update(re.findall(pattern, query, re.IGNORECASE))
        keywords = {"select", "from", "where", "and", "or", "as", "on"}
        return {t for t in tables if t.lower() not in keywords}

    def _create_query_pattern_hash(self, query: str) -> str:
        normalized = query.strip().upper()
        normalized = re.sub(r"'[^']*'", "'?'", normalized)
        normalized = re.sub(r"\b\d+\.?\d*\b", "?", normalized)
        normalized = " ".join(normalized.split())
        return hashlib.sha256(normalized.encode()).hexdigest()[:12]

    def _sanitize_query(self, query: str) -> str:
        # Strip SQL comments
        sanitized = re.sub(r"--[^\n]*", "", query)
        sanitized = re.sub(r"/\*.*?\*/", "", sanitized, flags=re.DOTALL)
        # Replace single-quoted string literals (handles escaped quotes)
        sanitized = re.sub(r"'(?:[^'\\]|\\.)*'", "'<VALUE>'", sanitized)
        # Replace double-quoted string literals
        sanitized = re.sub(r'"(?:[^"\\]|\\.)*"', '"<VALUE>"', sanitized)
        # Replace numeric literals
        sanitized = re.sub(r"\b\d+\.?\d*\b", "<NUM>", sanitized)
        return sanitized[:1000] + "..." if len(sanitized) > 1000 else sanitized

    def generate_summary(self) -> Dict:
        def convert_sets(obj):
            if isinstance(obj, set):
                return list(obj)
            elif isinstance(obj, dict):
                return {k: convert_sets(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_sets(i) for i in obj]
            return obj

        summary = {
            "analysis_period": {
                "start": self.start_time.isoformat() if self.start_time else None,
                "end": self.end_time.isoformat() if self.end_time else None,
            },
            "configuration": {
                "monitored_workgroups": list(MONITORED_WORKGROUPS),
                "monitored_s3_buckets": list(MONITORED_S3_BUCKETS),
                "analysis_mode": ANALYSIS_MODE,
                "multi_account_method": MULTI_ACCOUNT_METHOD,
            },
            "overview": {
                "total_athena_events": len(self.athena_events),
                "total_s3_events": len(self.s3_events),
                "query_execution_ids_found": len(self.query_execution_ids),
                "queries_fetched_from_athena": len(self.fetched_queries),
                "unique_users": len(self.user_stats),
                "unique_workgroups": len(self.workgroup_stats),
                "unique_databases": len(self.database_stats),
                "unique_query_patterns": len(self.query_patterns),
                "skipped_workgroups": list(self.skipped_workgroups),
                "skipped_buckets_count": len(self.skipped_buckets),
            },
            "workgroup_stats": convert_sets(dict(self.workgroup_stats)),
            "user_stats": convert_sets(dict(self.user_stats)),
            "database_stats": convert_sets(dict(self.database_stats)),
            "query_patterns": convert_sets(dict(self.query_patterns)),
            "s3_bucket_stats": convert_sets(dict(self.s3_bucket_stats)),
            "hourly_query_counts": dict(self.hourly_query_counts),
            "errors": self.errors,
        }
        if self.account_id:
            summary["account_id"] = self.account_id
        return summary

    def write_to_cloudwatch_logs(self):
        try:
            timestamp = datetime.now(timezone.utc)
            stream_name = f"analysis-{timestamp.strftime('%Y-%m-%d-%H-%M-%S')}"
            try:
                logs_client.create_log_stream(
                    logGroupName=LOG_GROUP_NAME, logStreamName=stream_name
                )
            except Exception:
                pass

            summary = self.generate_summary()
            log_events = [
                {
                    "timestamp": int(timestamp.timestamp() * 1000),
                    "message": json.dumps(
                        {"type": "SUMMARY", "data": summary["overview"]}
                    ),
                }
            ]

            for wg, stats in self.workgroup_stats.items():
                log_events.append(
                    {
                        "timestamp": int(timestamp.timestamp() * 1000),
                        "message": json.dumps(
                            {
                                "type": "WORKGROUP",
                                "workgroup": wg,
                                "query_count": stats["query_count"],
                                "unique_users": len(stats["users"]),
                            }
                        ),
                    }
                )

            for i in range(0, len(log_events), 100):
                batch = sorted(log_events[i : i + 100], key=lambda x: x["timestamp"])
                logs_client.put_log_events(
                    logGroupName=LOG_GROUP_NAME,
                    logStreamName=stream_name,
                    logEvents=batch,
                )
            logger.info(f"Wrote {len(log_events)} log events")
        except Exception as e:
            logger.error(f"Logs error: {str(e)}")
            self.errors.append({"source": "logs", "error": str(e)})

    def export_to_s3(self, per_account_summaries=None) -> str:
        try:
            timestamp = datetime.now(timezone.utc)
            zip_key = (
                f"exports/{timestamp.strftime('%Y/%m/%d')}/"
                f"athena-usage-{timestamp.strftime('%Y%m%d-%H%M%S')}.zip"
            )

            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                summary = self.generate_summary()
                if per_account_summaries:
                    summary["per_account"] = per_account_summaries
                zf.writestr(
                    "summary.json",
                    json.dumps(summary, indent=2, default=str),
                )
                zf.writestr(
                    "athena_events.json",
                    json.dumps(self.athena_events, indent=2, default=str),
                )
                zf.writestr(
                    "s3_events.json",
                    json.dumps(self.s3_events, indent=2, default=str),
                )

                lines = ["ATHENA USAGE REPORT", "=" * 60, ""]
                if ANALYSIS_MODE == "multi" and per_account_summaries:
                    lines.append(
                        f"Analysis Mode: Multi-Account "
                        f"({len(per_account_summaries)} accounts)"
                    )
                    lines.append("")
                for wg, stats in self.workgroup_stats.items():
                    lines.extend(
                        [
                            f"\nWorkgroup: {wg}",
                            f"  Queries: {stats['query_count']}",
                            f"  Users: {len(stats['users'])}",
                            f"  Data Scanned: "
                            f"{stats['total_data_scanned'] / (1024**3):.2f} GB",
                            f"  Query Types: {dict(stats['query_types'])}",
                        ]
                    )
                zf.writestr("workgroup_report.txt", "\n".join(lines))

                csv_lines = ["workgroup,query_count,unique_users,data_scanned_gb"]
                for wg, stats in self.workgroup_stats.items():
                    # Quote workgroup name to prevent CSV injection
                    safe_wg = '"' + wg.replace('"', '""') + '"'
                    csv_lines.append(
                        f"{safe_wg},{stats['query_count']},"
                        f"{len(stats['users'])},"
                        f"{stats['total_data_scanned'] / (1024**3):.4f}"
                    )
                zf.writestr("workgroup_stats.csv", "\n".join(csv_lines))

                if per_account_summaries:
                    zf.writestr(
                        "per_account_summary.json",
                        json.dumps(per_account_summaries, indent=2, default=str),
                    )

            zip_buffer.seek(0)
            # Omit ServerSideEncryption — bucket default encryption
            # (AES-256 or KMS) is applied automatically
            s3_client.put_object(
                Bucket=OUTPUT_BUCKET,
                Key=zip_key,
                Body=zip_buffer.getvalue(),
                ContentType="application/zip",
            )
            logger.info(f"Exported to s3://{OUTPUT_BUCKET}/{zip_key}")
            return f"s3://{OUTPUT_BUCKET}/{zip_key}"
        except Exception as e:
            logger.error(f"S3 export error: {str(e)}")
            self.errors.append({"source": "s3_export", "error": str(e)})
            return None


# ---------------------------------------------------------------------------
# Multi-account helpers
# ---------------------------------------------------------------------------


def merge_analyser(target, source):
    """Merge a per-account analyser's data into the aggregate analyser."""
    target.athena_events.extend(source.athena_events)
    target.s3_events.extend(source.s3_events)
    target.skipped_workgroups.update(source.skipped_workgroups)
    target.skipped_buckets.update(source.skipped_buckets)
    target.query_execution_ids.update(source.query_execution_ids)
    target.fetched_queries.update(source.fetched_queries)
    for k, v in source.query_patterns.items():
        t = target.query_patterns[k]
        t["count"] += v["count"]
        t["examples"] = list(set(t["examples"] + v["examples"]))[:5]
        t["users"].update(v["users"])
        t["workgroups"].update(v["workgroups"])
        t["databases"].update(v["databases"])
        t["tables"].update(v["tables"])
        t["total_data_scanned"] += v["total_data_scanned"]
        t["total_execution_time_ms"] += v["total_execution_time_ms"]
    for wg, stats in source.workgroup_stats.items():
        t = target.workgroup_stats[wg]
        t["query_count"] += stats["query_count"]
        t["users"].update(stats["users"])
        t["total_data_scanned"] += stats["total_data_scanned"]
        for qt, cnt in stats["query_types"].items():
            t["query_types"][qt] += cnt
    for uid, stats in source.user_stats.items():
        t = target.user_stats[uid]
        t["query_count"] += stats["query_count"]
        t["workgroups"].update(stats["workgroups"])
        t["databases"].update(stats["databases"])
        if stats["last_activity"]:
            if not t["last_activity"] or stats["last_activity"] > t["last_activity"]:
                t["last_activity"] = stats["last_activity"]
    for db, stats in source.database_stats.items():
        t = target.database_stats[db]
        t["query_count"] += stats["query_count"]
        t["tables"].update(stats["tables"])
        t["users"].update(stats["users"])
    for bkt, stats in source.s3_bucket_stats.items():
        t = target.s3_bucket_stats[bkt]
        t["get_count"] += stats["get_count"]
        t["put_count"] += stats["put_count"]
        t["list_count"] += stats["list_count"]
        t["prefixes"].update(stats["prefixes"])
        t["users"].update(stats["users"])
    for k, v in source.hourly_query_counts.items():
        target.hourly_query_counts[k] += v
    target.seen_event_ids.update(source.seen_event_ids)
    target.errors.extend(source.errors)


def analyse_account(account_id, start_time, end_time):
    """Analyse a single remote account via AssumeRole."""
    clients = get_cross_account_clients(account_id)
    if not clients:
        return None
    acct_analyser = AthenaUsageAnalyser(account_id=account_id)
    acct_analyser.process_cloudtrail_events(
        start_time,
        end_time,
        ct_client=clients["cloudtrail"],
        s3_cl=clients["s3"],
    )
    acct_analyser._fetch_query_strings(athena_cl=clients["athena"])
    acct_analyser._process_fetched_queries()
    return acct_analyser


def analyse_account_from_org_trail(account_id, start_time, end_time):
    """Analyse a single account using Organization Trail S3 data.

    Reads CloudTrail logs from the centralized org trail bucket (no AssumeRole
    needed for CloudTrail). Optionally enriches query data via cross-account
    role if available (adds execution stats like data scanned and timing).
    """
    acct_analyser = AthenaUsageAnalyser(account_id=account_id)
    acct_analyser._fetch_events_from_org_trail(account_id, start_time, end_time)

    # Try to enrich with Athena execution stats via cross-account role.
    # This is optional — query strings are already in CloudTrail.
    if acct_analyser.query_execution_ids:
        clients = get_cross_account_clients(account_id)
        if clients:
            acct_analyser._fetch_query_strings(athena_cl=clients["athena"])
            logger.info(
                f"Account {account_id}: enriched "
                f"{len(acct_analyser.fetched_queries)} queries with "
                f"execution stats"
            )
        else:
            logger.info(
                f"Account {account_id}: cross-account role not available, "
                f"using CloudTrail data only (query strings available, "
                f"execution stats are not)"
            )

    acct_analyser._process_fetched_queries()
    return acct_analyser


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------


def lambda_handler(event, context):
    logger.info("Lambda invoked with mode=%s", event.get("mode", MODE))

    run_mode = event.get("mode", MODE).upper()

    if "start_time" in event and "end_time" in event:
        try:
            start_time = datetime.fromisoformat(
                str(event["start_time"]).replace("Z", "+00:00")
            )
            end_time = datetime.fromisoformat(
                str(event["end_time"]).replace("Z", "+00:00")
            )
        except (ValueError, TypeError):
            return {
                "statusCode": 400,
                "body": {"message": "Invalid start_time or end_time format"},
            }
        # Guard against excessively large time ranges
        max_range_days = 90
        if (end_time - start_time).days > max_range_days:
            return {
                "statusCode": 400,
                "body": {
                    "message": f"Time range exceeds maximum of {max_range_days} days"
                },
            }
        if start_time >= end_time:
            return {
                "statusCode": 400,
                "body": {"message": "start_time must be before end_time"},
            }
    elif run_mode == "LOOKBACK":
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=LOOKBACK_MODE_DAYS)
    else:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=LOOKBACK_MINUTES)

    log_configuration_summary(run_mode, start_time, end_time)

    aggregate = AthenaUsageAnalyser()
    per_account_summaries = []

    if ANALYSIS_MODE == "multi" and MULTI_ACCOUNT_METHOD == "org":
        # AWS Organizations mode: auto-discover accounts, read from org trail
        discovered_accounts = discover_org_accounts()
        logger.info(f"Org mode: discovered {len(discovered_accounts)} member accounts")

        # Analyse the local (management) account first
        aggregate.process_cloudtrail_events(start_time, end_time)
        aggregate._fetch_query_strings()
        aggregate._process_fetched_queries()

        for i, account_id in enumerate(discovered_accounts):
            logger.info(
                f"--- Account {i + 1}/{len(discovered_accounts)}: "
                f"{account_id} (org trail) ---"
            )
            try:
                acct_analyser = analyse_account_from_org_trail(
                    account_id, start_time, end_time
                )
                if acct_analyser:
                    acct_summary = acct_analyser.generate_summary()
                    per_account_summaries.append(acct_summary)
                    merge_analyser(aggregate, acct_analyser)
                    logger.info(
                        f"Account {account_id}: "
                        f"{len(acct_analyser.athena_events)} athena events, "
                        f"{len(acct_analyser.fetched_queries)} queries"
                    )
            except Exception as e:
                logger.error(f"Error analysing account {account_id}: {str(e)}")
                per_account_summaries.append(
                    {
                        "account_id": account_id,
                        "error": str(e),
                        "overview": {
                            "total_athena_events": 0,
                            "total_s3_events": 0,
                        },
                    }
                )
        aggregate.start_time = start_time
        aggregate.end_time = end_time

    elif ANALYSIS_MODE == "multi" and MONITORED_ACCOUNTS:
        # Manual multi-account mode: explicit account IDs + AssumeRole
        logger.info(f"Multi-account mode: analysing {len(MONITORED_ACCOUNTS)} accounts")
        for i, account_id in enumerate(MONITORED_ACCOUNTS):
            logger.info(
                f"--- Account {i + 1}/{len(MONITORED_ACCOUNTS)}: {account_id} ---"
            )
            try:
                acct_analyser = analyse_account(account_id, start_time, end_time)
                if acct_analyser:
                    acct_summary = acct_analyser.generate_summary()
                    per_account_summaries.append(acct_summary)
                    merge_analyser(aggregate, acct_analyser)
                    logger.info(
                        f"Account {account_id}: "
                        f"{len(acct_analyser.athena_events)} athena events, "
                        f"{len(acct_analyser.fetched_queries)} queries fetched"
                    )
                else:
                    per_account_summaries.append(
                        {
                            "account_id": account_id,
                            "error": "Failed to assume role",
                            "overview": {
                                "total_athena_events": 0,
                                "total_s3_events": 0,
                            },
                        }
                    )
            except Exception as e:
                logger.error(f"Error analysing account {account_id}: {str(e)}")
                per_account_summaries.append(
                    {
                        "account_id": account_id,
                        "error": str(e),
                        "overview": {
                            "total_athena_events": 0,
                            "total_s3_events": 0,
                        },
                    }
                )
            # Rate-limit: 1-second delay between accounts to avoid CloudTrail
            # API throttling (2 req/sec limit)
            if i < len(MONITORED_ACCOUNTS) - 1:
                time.sleep(1)
        aggregate.start_time = start_time
        aggregate.end_time = end_time

    else:
        # Single-account mode — existing behaviour
        aggregate.process_cloudtrail_events(start_time, end_time)
        aggregate._fetch_query_strings()
        aggregate._process_fetched_queries()

    try:
        aggregate.write_to_cloudwatch_logs()
        export_location = aggregate.export_to_s3(
            per_account_summaries=(
                per_account_summaries if per_account_summaries else None
            )
        )
        summary = aggregate.generate_summary()

        if len(aggregate.athena_events) == 0:
            log_no_athena_events_warning(
                start_time, end_time, aggregate.skipped_workgroups
            )
        if len(aggregate.s3_events) == 0:
            log_no_s3_events_warning(start_time, end_time, aggregate.skipped_buckets)

        if len(aggregate.athena_events) > 0 or len(aggregate.s3_events) > 0:
            log_success_summary(
                len(aggregate.athena_events),
                len(aggregate.s3_events),
                len(aggregate.user_stats),
                len(aggregate.workgroup_stats),
                export_location,
                len(aggregate.fetched_queries),
            )

        result = {
            "statusCode": 200,
            "body": {
                "message": "Analysis completed",
                "mode": run_mode,
                "analysis_mode": ANALYSIS_MODE,
                "analysis_period": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                },
                "overview": summary["overview"],
                "export_location": export_location,
                "errors": aggregate.errors,
            },
        }
        if per_account_summaries:
            result["body"]["accounts_analysed"] = len(per_account_summaries)
            result["body"]["accounts_succeeded"] = len(
                [a for a in per_account_summaries if "error" not in a]
            )
        return result
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)
        return {
            "statusCode": 500,
            "body": {
                "message": "Analysis failed. Check CloudWatch Logs for details.",
                "error_count": len(aggregate.errors),
            },
        }
