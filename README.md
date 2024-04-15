#### Usage: create_sast_comparison.py [optional : <project_name>] <old_scan_date: YYYY-MM-DD> <new_scan_date: YYYY-MM-DD>

- For each project, if no scan was performed on the first (older) date, the next scan after that day will be considered.
- If no scan was performed on the second (newer) date, the last scan previous to that day will be considered.
- The CSV file will still show the dates you picked, even if the actual scan dates are different.
- To check the actual date and ID of each scan separately, refer to the console output.
- The script does not take into account failed or cancelled scans.

