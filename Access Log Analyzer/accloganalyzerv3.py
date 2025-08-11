#*********************************************************************************************************************
# Not the original author but modified the existing script to make it faster using AI (rgatti)
#
#
#  We have the original version of the script @ https://wwwin-github.cisco.com/CX-ACI/lv_accloganalyzer
#
#*********************************************************************************************************************

#!/usr/bin/env python3
import argparse
import os
import re
from datetime import datetime
from collections import defaultdict

ACCLOG_REGEX = re.compile(
    r"^(?P<RemoteAddrV6>::ffff|):?(?P<RemoteAddr>\d+\.\d+\.\d+\.\d+)\s?"
    r"(?:\((?:-|(?P<Real_RemoteAddrV6>::ffff|):?(?P<Real_RemoteAddr>\d+\.\d+\.\d+\.\d+))\).*)?"
    r".+\[(?P<TimeLocal>\d+\/\w+\/\d{4}:\d+:\d+:\d+).+]\s?"
    r'"(?P<Request>.*?)" (?P<Status>\d{3}) (?P<BodyBytesSent>\d+) '
    r'"(?P<HttpReferrer>.*?)" "(?P<HttpUserAgent>.*?)"'
)

BURST_THRESHOLD = 15


def mprint(msg):
    print(f"{datetime.now():%d-%b-%Y (%H:%M:%S.%f)} {msg}")


def parse_logs(filepath):
    with open(filepath, "r") as file:
        for line in file:
            match = ACCLOG_REGEX.match(line)
            if match:
                yield match.groupdict()


def summarize_logs(entries):
    remote_counts = defaultdict(int)
    real_ip_counts = defaultdict(int)
    user_agent_counts = defaultdict(int)
    status_counts = defaultdict(int)
    per_second_counts = defaultdict(list)

    logs = list(entries)
    if not logs:
        raise ValueError("No valid log entries found.")

    for entry in logs:
        remote_counts[entry["RemoteAddr"]] += 1
        real_ip_counts[entry["Real_RemoteAddr"]] += 1
        user_agent_counts[entry["HttpUserAgent"]] += 1
        status_counts[entry["Status"]] += 1

        ts = datetime.strptime(entry["TimeLocal"], "%d/%b/%Y:%H:%M:%S")
        per_second_counts[ts.strftime("%Y-%m-%d %H:%M:%S")].append(entry)

    first_time = datetime.strptime(logs[0]["TimeLocal"], "%d/%b/%Y:%H:%M:%S")
    last_time = datetime.strptime(logs[-1]["TimeLocal"], "%d/%b/%Y:%H:%M:%S")
    total_requests = len(logs)
    duration = (last_time - first_time).total_seconds()
    avg_qps = round(total_requests / duration, 2) if duration > 0 else 0

    summary = []
    summary.append("Access Log Time Analysis Summary:\n")
    summary.append(f"    Log Start Time: {logs[0]['TimeLocal']}")
    summary.append(f"    Log End Time: {logs[-1]['TimeLocal']}")
    summary.append(f"    Total # of Requests: {total_requests}")
    summary.append(f"    Time Coverage: {round(duration/60, 2)} minutes ({round(duration)} seconds)")
    summary.append(f"    Avg Requests/sec: {avg_qps}\n")

    burst_summary = []
    burst_total = 0
    for second, entries in per_second_counts.items():
        if len(entries) >= BURST_THRESHOLD:
            burst_total += 1
            burst_summary.append(f"\n{len(entries)} Request Burst found at {second}:")
            burst_summary.extend("    " + " ".join(str(v) for v in entry.values()) for entry in entries)

    summary.append(f"    Burst Summary: {burst_total} bursts of >= {BURST_THRESHOLD} req/sec found.\n")

    summary.append("\nRemote Address Summary:")
    for ip, count in remote_counts.items():
        pct = round((count / total_requests) * 100, 2)
        summary.append(f"    {ip}: {count} ({pct}%)")

    summary.append("\nReal IP Summary (via proxy):")
    for ip, count in real_ip_counts.items():
        pct = round((count / total_requests) * 100, 2)
        summary.append(f"    {ip}: {count} ({pct}%)")

    summary.append("\nUser-Agent Summary:")
    for agent, count in user_agent_counts.items():
        pct = round((count / total_requests) * 100, 2)
        summary.append(f"    {agent[:30]}...: {count} ({pct}%)")

    summary.append("\nHTTP Status Code Summary:")
    for code, count in status_counts.items():
        pct = round((count / total_requests) * 100, 2)
        summary.append(f"    {code}: {count} ({pct}%)")

    summary.append("\n============= Summary End =============\n")
    return "\n".join(summary), "\n".join(burst_summary)


def write_output(summary, burst_output, out_dir, timestamp):
    os.makedirs(out_dir, exist_ok=True)
    summary_file = os.path.join(out_dir, f"acclogSummary_{timestamp}.output")
    burst_file = os.path.join(out_dir, f"acclogBurst_{timestamp}.output")

    with open(summary_file, "w") as f:
        f.write(summary)
    mprint(f"Wrote Summary to {summary_file}")

    with open(burst_file, "w") as f:
        f.write(burst_output)
    mprint(f"Wrote Burst Analysis to {burst_file}")


def main(filename, output_dir):
    timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    mprint("Starting Log Analysis")

    try:
        entries = list(parse_logs(filename))
        summary, burst_output = summarize_logs(entries)
        write_output(summary, burst_output, output_dir, timestamp)
    except ValueError as e:
        mprint(f"Error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Access Log Analyzer with Burst Detection")
    parser.add_argument(
        "-f", "--file", default="/var/log/dme/log/access.log",
        help="Full path to access.log file to analyze"
    )
    parser.add_argument(
        "-o", "--output", default="/data/techsupport",
        help="Directory to write output files"
    )
    args = parser.parse_args()

    if os.path.isfile(args.file):
        main(args.file, args.output)
    else:
        mprint(f"File not found: {args.file}")

