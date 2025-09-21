# Cyber Log Analyzer

Cyber Log Analyzer is a Python-based cybersecurity tool designed to monitor and detect suspicious login activity, failed login spikes, and unusual IP/user-agent behavior. It integrates with Splunk, Power BI, and SQLite for efficient visualization and incident tracking.

## Features
- Detects failed login spikes (multiple failed attempts from the same IP)
- Identifies suspicious user agents using regex patterns
- Stores alerts in a local SQLite database
- Exports data for Power BI visualization
- Supports Splunk integration for advanced log management

## Tech Stack
- **Python** (pandas, sqlite3, regex)
- **SQLite** (local database for alerts)
- **Power BI** (visualization)
- **Splunk** (log aggregation & monitoring)
- **Git** (version control)

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/<your-username>/cyber-log-analyzer.git
2. Navigate to the project folder:

cd cyber-log-analyzer/cyber_log_analyzer


3. Install dependencies:

pip install -r requirements.txt

Usage

Place your logs in the data/ folder (sample_logs.csv included as an example)

Configure regex patterns in config/regex_patterns.md

Run the log analyzer:

python log_analyzer.py


Alerts will be stored in cyber_logs.db and printed to the console

Use exported files for Power BI dashboards or Splunk integration

Contributing

Feel free to fork this repository and submit pull requests. Issues and suggestions are welcome!

License

This project is open-source and free to use.
