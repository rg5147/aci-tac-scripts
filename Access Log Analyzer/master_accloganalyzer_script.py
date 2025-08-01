#*********************************************************************************************************************
#author rgatti
#
# THIS SCRIPT HAS TO BE EXECUTED ON LOGVIEWER.
# This script is to review the access logs file (including .gz file) on each apic and provide a comprehensive list 
# of IPs probing the APICs including self IPs. This is useful for troubleshooting slow UI cases.
#
# This script produces 4 output files:
#  1. Aggregated access logs "combined_access.log" per node 
#  2. acclogSummary_xx.output file for each node 
#  3. acclogBurst_xx.output file for each node
#  4. Comprehensive Aggregated Real IP Summary "Aggregated_Real_IP_Summary.txt" that combines the info for all apic nodes plus individual node Real IP Summary 
# 
#  Requirement:
#  Decode the APIC show techs log3of3 using spman or log-decoder 
#  Execute the below script from the dnld_xxx folder
#  The script is dependent on another script accloganalyzerv3.py. Add this script as well as the master_accloganalyzer_script.py to your local scripts folder (example /users/rgatti/scripts). 
#  Ensure that the folder is added to your PATH. 
#
# Usage: cd /users/<cec>/dnld_xxxxx
#         python3 /users/<cec>/scripts/master_accloganalyzer_script.py
#
#  Note: we have another script that can be executed on the APIC.
#  https://github.com/datacenter/aci-tac-scripts/tree/main/Access%20Log%20Analyzer
#
#  We also have a older version of the script @ https://wwwin-github.cisco.com/CX-ACI/lv_accloganalyzer
#
#*********************************************************************************************************************



import os
import glob
import gzip
import subprocess
import re

def aggregate_access_logs(node_base_path):
    """
    Aggregates access logs for a given node path into combined_access.log files.
    Searches for directories matching the pattern './node-x/*/*/data/log/'.
    Returns a list of paths to the created combined_access.log files.
    """
    combined_log_paths = []
    # Search for data/log directories within the node's structure
    # The pattern is ./node-x/*/*/data/log/
    log_dirs = glob.glob(os.path.join(node_base_path, "*", "*", "data", "log"))

    if not log_dirs:
        print(f"  No 'data/log' directories found under {node_base_path} matching the pattern.")
        return combined_log_paths

    for log_dir in log_dirs:
        print(f"  Processing log directory: {log_dir}")
        combined_access_log_path = os.path.join(log_dir, "combined_access.log")

        # Clear existing combined file content before writing
        try:
            open(combined_access_log_path, 'w', encoding='utf-8').close()
        except IOError as e:
            print(f"    Error clearing {combined_access_log_path}: {e}. Skipping this directory.")
            continue

        # Get all access log files, gzipped and uncompressed
        all_log_files_in_dir = glob.glob(os.path.join(log_dir, "access.log*"))

        gzipped_files = []
        plain_access_log = None

        for f in all_log_files_in_dir:
            if f.endswith(".gz"):
                gzipped_files.append(f)
            elif os.path.basename(f) == "access.log":
                plain_access_log = f

        # Sort gzipped files to ensure chronological order (e.g., access.log-20230101.gz before access.log-20230102.gz,
        # or access.log.1.gz before access.log.2.gz). Simple sort works for common naming conventions.
        gzipped_files.sort()

        try:
            with open(combined_access_log_path, 'a', encoding='utf-8') as outfile:
                # Process gzipped files first (older logs)
                for gz_file in gzipped_files:
                    try:
                        with gzip.open(gz_file, 'rt', encoding='utf-8') as infile:
                            outfile.write(infile.read())
                    except Exception as e:
                        print(f"    Warning: Error processing gzipped file {gz_file}: {e}")

                # Then append the current access.log (newest log)
                if plain_access_log and os.path.exists(plain_access_log):
                    try:
                        with open(plain_access_log, 'r', encoding='utf-8') as infile:
                            outfile.write(infile.read())
                    except Exception as e:
                        print(f"    Warning: Error processing plain access log {plain_access_log}: {e}")
            combined_log_paths.append(combined_access_log_path)
            print(f"    Aggregated logs to: {combined_access_log_path}")
        except Exception as e:
            print(f"    Error writing combined log to {combined_access_log_path}: {e}")

    return combined_log_paths

def run_accloganalyzer(combined_log_paths):
    """
    Runs accloganalyzerv3.py on each combined_access.log file.
    The output files (acclogSummary) will be placed in the same directory as the input log.
    """
    if not combined_log_paths:
        print("  No combined_access.log files to analyze.")
        return

    print("\n--- Running accloganalyzerv3.py on combined logs ---")
    for log_path in combined_log_paths:
        log_dir = os.path.dirname(log_path)
        print(f"  Running accloganalyzerv3.py for {os.path.basename(log_path)}, output to {log_dir}")
        try:
            # Assuming accloganalyzerv3.py is in the current working directory or in PATH
            result = subprocess.run(
                ["accloganalyzerv3.py", "-f", log_path, "-o", log_dir],
                capture_output=True, # Capture stdout and stderr
                text=True,           # Decode stdout/stderr as text
                check=True           # Raise CalledProcessError if the command returns a non-zero exit code
            )
            # print(f"    accloganalyzerv3.py output:\n{result.stdout.strip()}") # Uncomment for verbose output
            if result.stderr:
                print(f"    accloganalyzerv3.py errors:\n{result.stderr.strip()}")
        except FileNotFoundError:
            print("    Error: accloganalyzerv3.py not found. Make sure it's in the current directory or in your system's PATH.")
        except subprocess.CalledProcessError as e:
            print(f"    Error running accloganalyzerv3.py for {log_path}: Command failed with exit code {e.returncode}")
            print(f"    Stdout: {e.stdout.strip()}")
            print(f"    Stderr: {e.stderr.strip()}")
        except Exception as e:
            print(f"    An unexpected error occurred while running accloganalyzerv3.py for {log_path}: {e}")

def extract_and_aggregate_summary():
    """
    Finds all acclogSummary files and extracts the "Real IP Summary (via proxy):" section.
    Aggregates the extracted content into a single file named Aggregated_Real_IP_Summary.txt.
    Also provides a comprehensive aggregated view at the end.
    """
    output_summary_file = "Aggregated_Real_IP_Summary.txt"
    summary_file_pattern = "*acclogSummary*"
    
    # Dictionary to store the comprehensive aggregated IP counts
    comprehensive_ip_summary = {}

    # Find all acclogSummary files recursively from the current directory
    all_summary_files = glob.glob(f"./**/{summary_file_pattern}", recursive=True)
    all_summary_files.sort() # Sort for consistent output order

    print(f"\n--- Extracting and Aggregating Real IP Summary ---")
    if not all_summary_files:
        print("  No acclogSummary files found. Skipping aggregation of Real IP Summary.")
        return

    print(f"  Found {len(all_summary_files)} acclogSummary files.")
    print(f"  Aggregating to: {output_summary_file}")

    try:
        with open(output_summary_file, 'w', encoding='utf-8') as outfile:
            outfile.write("--- Individual Node Real IP Summaries ---\n\n")
            for i, summary_file in enumerate(all_summary_files):
                print(f"  Extracting from {summary_file}")
                in_section = False
                section_content = []
                try:
                    with open(summary_file, 'r', encoding='utf-8') as infile:
                        for line in infile:
                            if line.strip().startswith("Real IP Summary (via proxy):"):
                                in_section = True
                                section_content.append(line) # Include the header line
                            elif in_section:
                                # Check if it's the end marker
                                if line.strip().startswith("User-Agent Summary:"):
                                    in_section = False
                                    section_content.append(line) # Include the end marker line
                                    break # Stop after including the end marker line (as per sed behavior)
                                
                                section_content.append(line)
                                
                                # Parse line for comprehensive aggregation if it's an IP:count line
                                # Updated regex to handle the "(PERCENTAGE%)" part
                                match = re.match(r'^\s*(\S+):\s*(\d+)\s*\(.*\)\s*$', line)
                                if match:
                                    ip = match.group(1).strip()
                                    count = int(match.group(2))
                                    comprehensive_ip_summary[ip] = comprehensive_ip_summary.get(ip, 0) + count
                                # Handle "None" case if it appears without percentage, or if percentage isn't always there
                                elif re.match(r'^\s*(\S+):\s*(\d+)\s*$', line): # Fallback for lines without percentage
                                    match_no_perc = re.match(r'^\s*(\S+):\s*(\d+)\s*$', line)
                                    if match_no_perc:
                                        ip = match_no_perc.group(1).strip()
                                        count = int(match_no_perc.group(2))
                                        comprehensive_ip_summary[ip] = comprehensive_ip_summary.get(ip, 0) + count
                                    
                    if section_content:
                        outfile.write(f"--- From {summary_file} ---\n")
                        outfile.writelines(section_content)
                        outfile.write("\n") # Add a newline for separation between files
                    else:
                        print(f"  Warning: 'Real IP Summary (via proxy):' section not found or empty in {summary_file}")

                except Exception as e:
                    print(f"  Error processing summary file {summary_file}: {e}")
            
            # Add the comprehensive aggregated view
            outfile.write("\n\n--- Comprehensive Aggregated Real IP Summary ---\n")
            if comprehensive_ip_summary:
                # Sort by IP (key)
                sorted_ips = sorted(comprehensive_ip_summary.keys())
                for ip in sorted_ips:
                    outfile.write(f"{ip}: {comprehensive_ip_summary[ip]}\n")
            else:
                outfile.write("No comprehensive IP summary data found.\n")

        print(f"  Successfully created {output_summary_file}")
    except Exception as e:
        print(f"  Error writing to {output_summary_file}: {e}")

def main():
    all_combined_log_paths = []
    print("--- Starting Log Aggregation ---")
    for x in range(1, 8): # Iterate from node-1 to node-7
        node_base_path = f"./node-{x}"
        if os.path.exists(node_base_path):
            print(f"\nProcessing {node_base_path}...")
            combined_log_paths_for_node = aggregate_access_logs(node_base_path)
            all_combined_log_paths.extend(combined_log_paths_for_node)
        else:
            print(f"\nDirectory {node_base_path} does not exist. Skipping.")

    if not all_combined_log_paths:
        print("\nNo combined_access.log files were created across all nodes. Cannot proceed with analysis or summary extraction.")
        return

    # Step 2: Run accloganalyzerv3.py
    run_accloganalyzer(all_combined_log_paths)

    # Step 3: Extract and Aggregate Real IP Summary
    extract_and_aggregate_summary()

    print("\nScript finished successfully.")

if __name__ == "__main__":
    main()