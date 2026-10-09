# Airgap Sentinel — Log Analysis & Threat Detection Platform

Airgap Sentinel is a lightweight cybersecurity prototype designed
to collect, parse, and analyze security logs in isolated network
environments.

It provides log ingestion, rule-based threat detection, alert
management, threat intelligence lookup, and report generation.
The project also includes an offline update workflow.

## Key Features

- Log ingestion and parsing through a FastAPI backend.
- Detection of repeated failed login attempts.
- Detection of suspicious login times.
- Threat intelligence matching.
- Alert creation and lifecycle management.
- Security report generation.
- Offline update-package import and verification workflow.
- Browser-based frontend.
- Automated API and detection-engine tests.

## Technology Stack

- Python
- FastAPI
- SQLAlchemy
- SQLite by default, with database configuration through
  `DATABASE_URL`
- HTML, CSS, and JavaScript
- pytest
- Uvicorn

## Project Structure

```text
airgap-sentinel/
├── backend/
│   └── log_ingestion/
│       ├── database.py
│       ├── main.py
│       ├── models.py
│       ├── parser.py
│       ├── routes.py
│       └── schemas.py
├── frontend/
│   ├── app.js
│   ├── index.html
│   └── style.css
├── member2_only/
│   ├── detection_engine/
│   ├── tests/
│   ├── api.py
│   └── demo.py
├── updates/
│   ├── incoming/
│   ├── verified/
│   ├── create_update.py
│   └── verify_update.py
├── docs/
│   └── architecture.md
├── sample_data/
│   └── sample_auth.log
├── tests/
├── .env.example
├── requirements.txt
└── LICENSE
```

## Prerequisites

- Python 3.12 recommended for the tested development environment.
- pip.
- Git.

PostgreSQL is not required when using the default SQLite configuration.
If you configure PostgreSQL, you must install and configure the
appropriate database driver and database service.

## Installation

Clone the repository:

```bash
git clone https://github.com/azimfathima999/airgap-sentinel.git
cd airgap-sentinel
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the root dependencies:

```bash
python -m pip install -r requirements.txt
```

## Database Configuration

The backend defaults to a local SQLite database:

```text
sqlite:///./airgap_sentinel.db
```

To override the database URL, create a `.env` file in the project
root and configure `DATABASE_URL`.

For example, for a local SQLite database:

```env
DATABASE_URL=sqlite:///./airgap_sentinel.db
```

The application loads environment variables using `python-dotenv`.

Do not commit real credentials or secrets.

## Run the Backend

From the repository root, activate the virtual environment and run:

```bash
python -m uvicorn backend.log_ingestion.main:app --reload
```

The API should be available at:

- API root: http://127.0.0.1:8000/
- Health check: http://127.0.0.1:8000/health
- Interactive API documentation: http://127.0.0.1:8000/docs

Use the interactive API documentation to inspect available endpoints.

## Run the Tests

Run the automated test suite:

```bash
python -m pytest -v
```

The current development test suite has passed 27 tests covering
API operations, log parsing, detection rules, alerts, threat
intelligence, and reporting.

Test results may vary if the code or environment changes.

## Sample Data

Synthetic authentication events are available in:

`sample_data/sample_auth.log`

The sample contains a successful login followed by five failed
login attempts from the same source address.

The detection engine's tests verify that five failed logins within
five minutes trigger Rule 001 under its current configuration.

Use the sample file to understand the event pattern. The file is
not automatically ingested simply because it exists in the repository.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the system
components, data flow, security considerations, and architecture
diagram.

## Offline Updates

The `updates/` directory contains scripts and example packages
for the offline update workflow.

Review the update verification code and its tests before using
the mechanism in a security-sensitive environment. USB transfer
alone does not guarantee update authenticity or network isolation.

## Security Limitations

- This is a prototype and requires security testing before production use.
- Detection depends on the implemented rules and available log data.
- Automated responses must be restricted to explicitly approved actions.
- Network isolation and one-way data flow must be validated separately.
- Use synthetic logs for demonstrations and avoid committing sensitive data.

## License

This project declares the MIT License. See the `LICENSE` file.