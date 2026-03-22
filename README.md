# Data Security with Blockchain and AI

A role-based healthcare application built with FastAPI, PostgreSQL, WebAuthn, encryption, audit logging, blockchain-style integrity tracking, risk scoring, and WebRTC video calling.

This project is designed around a healthcare workflow where patients, doctors, lab assistants, and an administrator interact with sensitive medical data under explicit role controls. Medical records are encrypted before storage, hashed for tamper detection, tracked in a hash-chained ledger, and monitored through audit-driven AI risk scoring.

## Table of Contents

- [Overview](#overview)
- [Key Capabilities](#key-capabilities)
- [Roles and Access Model](#roles-and-access-model)
- [Architecture](#architecture)
- [Security Design](#security-design)
- [Core Workflows](#core-workflows)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [API Surface](#api-surface)
- [UI Routes](#ui-routes)
- [Data Model](#data-model)
- [ML Risk Engine](#ml-risk-engine)
- [Storage and Integrity Behavior](#storage-and-integrity-behavior)
- [Operational Notes and Limitations](#operational-notes-and-limitations)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Overview

The application combines several security controls into one system:

- Password + fingerprint/passkey authentication using WebAuthn
- JWT-secured API access with server-side session support for dashboard pages
- Role-based access control across Admin, Doctor, Patient, and Lab Assistant users
- Encrypted medical-record storage using Fernet
- SHA-256 hashing for file integrity verification
- Blockchain-style append-only ledger entries for important events
- Audit events and risk alerts for suspicious activity
- WebRTC doctor-patient video calling with FastAPI WebSocket signaling
- Healthcare workflow support for appointments, lab requests, reports, and prescriptions

This is a monolithic FastAPI application with:

- Server-rendered Jinja templates in `Templates/`
- Static JavaScript and CSS in `static/`
- Application logic in `backend/app/`
- PostgreSQL as the primary relational store
- Local filesystem storage for encrypted and quarantined files

## Key Capabilities

- Secure registration and login with password plus WebAuthn biometric/passkey verification
- Single-admin enforcement: only one admin account may exist
- Patient appointment booking with doctor approval workflow
- Encrypted medical-record upload and verified download
- Automatic file quarantine on tamper detection or decryption failure
- Lab request creation by doctors and report upload by lab assistants
- Prescription authoring and downloadable prescription text files
- Admin dashboard for registered users, AI risk events, and blockchain verification
- API endpoints for record-access requests and decisions
- Video room creation, signaling, and browser-based doctor-patient calls
- Optional ML model training for risk scoring, with heuristic fallback when no model artifact is present

## Roles and Access Model

### Supported roles

- `Admin`
- `Doctor`
- `Patient`
- `Lab Assistant`

### Role summary

| Role | Primary capabilities |
| --- | --- |
| Admin | View registered users, inspect risk events, verify ledger integrity, access admin APIs, download prescriptions |
| Doctor | Approve appointments, review patient records, create lab requests, write prescriptions, create video rooms |
| Patient | Register/login, upload records, book appointments, view reports and prescriptions, join video rooms |
| Lab Assistant | View lab requests, upload lab reports, access reports they completed |

### Important rule

- The system now enforces a single-admin policy.
- After the first admin is created, the registration UI hides the `Admin` option.
- The backend also rejects any second admin registration attempt.
- Doctor, patient, and lab assistant accounts can be created without this restriction.

## Architecture

```text
Browser
├─ Jinja dashboard pages
├─ Auth JS (WebAuthn)
└─ Video JS (WebRTC + WebSocket signaling)
           |
           v
FastAPI Application
├─ HTML routes for dashboards and downloads
├─ JSON APIs under /api
├─ Session middleware for UI
├─ JWT auth for API and video access
├─ Services layer
│  ├─ authentication
│  ├─ audit logging
│  ├─ ledger block creation
│  ├─ record encryption/decryption
│  ├─ tamper quarantine
│  └─ risk scoring
├─ PostgreSQL
│  ├─ users
│  ├─ appointments
│  ├─ records metadata
│  ├─ audit events
│  ├─ ledger blocks
│  ├─ risk alerts
│  ├─ lab requests
│  └─ prescriptions
└─ Local storage
   ├─ backend/storage/encrypted
   └─ backend/storage/quarantined
```

### High-level design notes

- The application is a single FastAPI service, not a microservices system.
- The "blockchain" component is a database-backed hash chain, not a decentralized blockchain network.
- The frontend is server-rendered with small JavaScript modules for authentication and calling; there is no Node-based build step.
- Files are stored on local disk, while their metadata and integrity history live in PostgreSQL.

## Security Design

### Authentication

- Passwords are normalized with SHA-256 and then hashed with bcrypt.
- Registration and login both require WebAuthn verification.
- WebAuthn is configured for:
  - platform authenticators
  - resident keys
  - user verification
- The browser obtains WebAuthn options from the backend, completes the challenge locally, and sends the signed credential back for verification.

### Authorization

- JWT bearer tokens secure the JSON API layer.
- A server-side session is also created for dashboard navigation after successful login.
- Role checks are enforced in API endpoints and dashboard routes.

### Record protection

- Uploaded medical files are encrypted with Fernet before being written to disk.
- A SHA-256 hash of the plaintext is stored in the database.
- File access verifies decryption success and compares the live hash to the stored hash.
- On mismatch or read/decrypt failure, the file is quarantined and access is blocked.

### Audit and ledger

- Authentication failures, WebAuthn failures, video connection events, and tamper incidents generate audit events.
- Important events are also written to a hash-chained `ledger_blocks` table.
- The admin verification page recomputes the chain and reports ledger integrity.

### Risk scoring

- Risk scores are derived from recent audit activity.
- High-risk situations create `risk_alerts` entries for admin review.
- If no trained ML artifact exists, the system falls back to a heuristic score.

## Core Workflows

### 1. Registration

1. User enters name, email, password, and role.
2. Frontend requests `/api/auth/register/options`.
3. Browser creates a WebAuthn credential.
4. Frontend submits `/api/auth/register/verify`.
5. Backend stores the password hash, user profile, and WebAuthn credential.
6. A ledger event is created for successful WebAuthn registration.

### 2. Login

1. User enters email and password.
2. Backend validates the password and returns WebAuthn challenge options.
3. Browser completes biometric/passkey verification.
4. Backend verifies the assertion and issues a JWT.
5. Frontend stores the JWT and posts it to `/ui/session` to establish the dashboard session.

### 3. Patient medical-record upload

1. Patient uploads a file from the dashboard.
2. Backend encrypts the file with Fernet.
3. Backend stores the encrypted file in `backend/storage/encrypted`.
4. Metadata and SHA-256 hash are saved in PostgreSQL.
5. A ledger block is appended for the upload event.

### 4. Record download and tamper handling

1. User requests a file download.
2. Backend checks role-based access.
3. Encrypted bytes are read and decrypted.
4. The decrypted file hash is recomputed.
5. If the hash mismatches or file access fails:
   - the file is moved to quarantine
   - the record status becomes `QUARANTINED`
   - an audit event and risk alert are created
   - access is denied

### 5. Appointment workflow

1. Patient books an appointment with a doctor.
2. Doctor reviews the appointment request.
3. Doctor approves the appointment.
4. Approved appointments drive doctor access to patient content in the dashboard workflow.

### 6. Lab workflow

1. Doctor creates a lab request for an approved patient.
2. Lab assistant sees pending requests.
3. Lab assistant uploads the report file.
4. The report is stored as an encrypted medical record.
5. The lab request is marked `COMPLETED`.
6. Patient and doctor can download the resulting report.

### 7. Prescription workflow

1. Doctor writes a prescription for an approved patient.
2. Prescription data is stored in PostgreSQL.
3. Patients and doctors can download it as a plain-text file.
4. Admin users can also download prescriptions.

### 8. Video consultation workflow

1. Patient sends their patient ID to a selected doctor.
2. Doctor creates a room through `/api/video/sessions`.
3. Doctor shares the generated room ID back to the patient dashboard.
4. Both parties join the room.
5. WebRTC offer/answer and ICE messages are relayed over a FastAPI WebSocket.

## Technology Stack

### Backend

- Python 3.11
- FastAPI
- SQLAlchemy 2.x
- PostgreSQL 16
- Jinja2
- JOSE JWT
- bcrypt
- cryptography / Fernet
- WebAuthn

### Machine learning

- scikit-learn
- numpy
- scipy
- joblib

### Frontend

- Server-rendered HTML templates
- Vanilla JavaScript
- WebAuthn browser APIs
- WebRTC
- WebSocket signaling

### Infrastructure

- Docker
- Docker Compose

## Project Structure

```text

├─ Templates/
│  ├─ admin_dashboard.html
│  ├─ base.html
│  ├─ blockchain_status.html
│  ├─ doctor_dashboard.html
│  ├─ lab_dashboard.html
│  ├─ landing.html
│  ├─ login.html
│  ├─ patient_dashboard.html
│  └─ register.html
|
├─ backend/
│  ├─ .env
│  ├─ .env.example
│  ├─ requirements.txt
│  ├─ app/
│  │  ├─ init.py
│  │  ├─ main.py
│  │  ├─ models.py
│  │  ├─ schemas.py
│  │  ├─ services.py
│  │  ├─ api/
│  │  │  ├─ admin.py
│  │  │  ├─ auth.py
│  │  │  ├─ deps.py
│  │  │  ├─ health.py
│  │  │  ├─ init.py
│  │  │  ├─ records.py
│  │  │  ├─ risk.py
│  │  │  ├─ router.py
│  │  │  └─ video.py
│  │  ├─ core/
│  │  │  ├─ config.py
│  │  │  ├─ init.py
│  │  │  ├─ rbac.py
│  │  │  ├─ security.py
│  │  │  └─ webauthn_core.py
│  │  ├─ db/
│  │  │  ├─ base.py
│  │  │  ├─ init.py
│  │  │  ├─ init_db.py
│  │  │  └─ session.py
│  │  └─ ml/
│  │     ├─ inference.py
│  │     ├─ init.py
│  │     └─ train_risk_model.py
│  └─ storage/
│     ├─ encrypted/
│     └─ quarantined/
|
|─ static/
│  ├─ hospital-bg.jpg
│  ├─ css/
│  │  └─ style.css
│  └─ js/
│     ├─ api.js
│     ├─ auth.js
│     ├─ video_call.js
│     └─ webauthn.js
|
├─ .gitignore
├─ Dockerfile
├─ README.md
├─ docker-compose.yml
├─ dockerignore
```

### Directory notes

- `Templates/` contains the server-rendered dashboards and auth pages.
- `static/` contains CSS plus JavaScript for API calls, WebAuthn, and WebRTC calling.
- `backend/app/` contains all application code.
- `backend/storage/` is runtime storage for encrypted and quarantined files.
- `uploads/` contains sample/demo assets in this workspace and is not the primary runtime storage path used by the backend.

## Getting Started

### Prerequisites

- Python 3.11+
- PostgreSQL 16+ or Docker Desktop
- A modern browser with WebAuthn support
- Localhost or HTTPS for WebAuthn to function correctly

### Option 1: Run with Docker Compose

From the project root:

```bash
docker compose up --build
```

This starts:

- `db` on `localhost:5432`
- `backend` on `http://localhost:8000`

The container entrypoint automatically runs:

```bash
python -m app.db.init_db
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Option 2: Run locally without Docker

1. Copy the sample environment file.

```bash
cp backend/.env.example backend/.env
```

2. Edit `backend/.env` with your database URL, JWT secret, WebAuthn origin, and Fernet key.

3. Create and activate a virtual environment.

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
```

4. Install dependencies.

```bash
pip install -r requirements.txt
```

5. Ensure PostgreSQL is running and the target database exists.

6. Initialize the database schema.

```bash
python -m app.db.init_db
```

7. Optionally train the ML model.

```bash
python -m app.ml.train_risk_model
```

8. Start the app.

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

9. Open:

- App: `http://localhost:8000`
- OpenAPI docs: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Environment Variables

The project reads configuration from `backend/.env`.

| Variable | Purpose | Default / Example |
| --- | --- | --- |
| `APP_NAME` | FastAPI application title | `Data Security Using Blockchain and AI` |
| `DEBUG` | FastAPI debug mode | `true` |
| `API_PREFIX` | Prefix for JSON APIs | `/api` |
| `CORS_ORIGINS` | Allowed browser origins | `["http://localhost:8000"]` |
| `DATABASE_URL` | PostgreSQL SQLAlchemy URL | `postgresql+psycopg://postgres:postgres@localhost:5432/medsec_ai` |
| `JWT_SECRET` | JWT signing secret | set a long random value |
| `JWT_ALG` | JWT algorithm | `HS256` |
| `JWT_EXP_MINUTES` | Token lifetime used by JWT creation | `480` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Alternate token lifetime setting supported by config | `60` |
| `RP_ID` | WebAuthn relying-party ID | `localhost` |
| `RP_NAME` | WebAuthn relying-party name | `MedSec AI` |
| `EXPECTED_ORIGIN` | Expected WebAuthn browser origin | `http://localhost:8000` |
| `FERNET_KEY` | File-encryption key | generate your own |
| `STORAGE_DIR` | Base storage path | `storage` |
| `ENCRYPTED_DIR` | Encrypted-file directory | `storage/encrypted` |
| `QUARANTINED_DIR` | Quarantine directory | `storage/quarantined` |
| `RISK_MODEL_PATH` | Path to the trained ML artifact | `app/ml/artifacts/risk_model.pkl` |

Generate a Fernet key with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## API Surface

All JSON APIs are mounted under `API_PREFIX`, which defaults to `/api`.

### Health

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Health check and DB connectivity probe |

### Authentication

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/auth/register/options` | Start WebAuthn registration |
| `POST` | `/api/auth/register/verify` | Finish registration |
| `POST` | `/api/auth/login/options` | Start WebAuthn login |
| `POST` | `/api/auth/login/verify` | Finish login and issue JWT |
| `POST` | `/api/auth/webauthn/fail` | Log WebAuthn failures |

### Records

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/records/upload` | Upload an encrypted record |
| `GET` | `/api/records/{record_id}/download` | Download a record with access checks |
| `POST` | `/api/records/access/request` | Doctor requests patient access |
| `GET` | `/api/records/access/pending` | Patient lists pending access requests |
| `POST` | `/api/records/access/decide` | Patient approves or rejects access |

### Risk

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/risk/me` | Current user risk score and features |
| `GET` | `/api/risk/user/{user_id}` | Admin-only risk lookup for another user |

### Admin

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/admin/risk-alerts` | List recent risk alerts |
| `GET` | `/api/admin/audit` | List recent audit events |

### Video

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/video/sessions` | Doctor creates a video room for a patient |
| `WS` | `/api/video/ws/{room_id}` | WebSocket signaling for WebRTC |

## UI Routes

### Public and shared pages

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Redirect to the current user's dashboard |
| `GET` | `/login` | Login page |
| `GET` | `/register` | Registration page |
| `GET` | `/logout` | Logout and clear session |
| `POST` | `/ui/session` | Mirror JWT identity into the server-side session |

### Admin UI

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/admin` | Admin dashboard |
| `GET` | `/verify_blockchain` | Ledger and file-integrity verification page |

### Patient UI

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/patient` | Patient dashboard |
| `POST` | `/patient` | Compatibility alias used by the current appointment form |
| `POST` | `/patient/book` | Book appointment |
| `POST` | `/patient/upload` | Upload medical record |
| `POST` | `/patient/video/send-id` | Send patient ID to doctor dashboard |

### Doctor UI

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/doctor` | Doctor dashboard |
| `GET` | `/doctor/appointments/{appointment_id}/approve` | Approve appointment |
| `POST` | `/doctor/labrequest` | Compatibility alias used by the current lab-request form |
| `POST` | `/doctor/lab` | Create lab request |
| `POST` | `/doctor/prescribe` | Compatibility alias used by the current prescription form |
| `POST` | `/doctor/prescription` | Create prescription |
| `POST` | `/doctor/video/send-room` | Send generated room ID to patient dashboard |

### Lab UI

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/labassistant` | Lab assistant dashboard |
| `POST` | `/labassistant/complete` | Complete request and upload report |
| `POST` | `/labassistant/requests/{request_id}/upload` | Upload report for a specific request |

### Downloads

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/download/{record_id}` | Download a medical record or lab report |
| `GET` | `/prescriptions/{prescription_id}/download` | Download a prescription text file |

## Data Model

| Table | Purpose |
| --- | --- |
| `users` | User identities, roles, password hashes, WebAuthn user handles |
| `webauthn_credentials` | Registered authenticators/passkeys |
| `webauthn_challenges` | Pending registration/login challenges |
| `audit_events` | Security and behavioral event log |
| `ledger_blocks` | Hash-chained audit-style integrity ledger |
| `medical_records` | Record metadata, status, file path, SHA-256 hash |
| `access_requests` | Doctor-to-patient access approval requests |
| `record_permissions` | Approved patient-doctor record permissions |
| `appointments` | Patient-doctor appointment workflow |
| `video_sessions` | Doctor-patient video room records |
| `risk_alerts` | Risk score outputs linked to suspicious activity |
| `lab_requests` | Doctor-issued lab requests and report references |
| `prescriptions` | Structured prescription records |

## ML Risk Engine

### Inputs

The risk engine computes recent security features from audit history:

- `failed_auth_10m`
- `password_failed_10m`
- `denied_access_1h`
- `tamper_24h`
- `new_device_24h`

### Runtime behavior

- If `RISK_MODEL_PATH` exists, the app loads a pickled scikit-learn logistic regression model and returns an ML-based risk score.
- If the artifact is missing, the app uses a heuristic fallback.
- Risk severities are classified as:
  - `LOW` for scores below 40
  - `MEDIUM` for scores from 40 to 79
  - `HIGH` for scores 80 and above

### Training

Train the bundled synthetic model with:

```bash
cd backend
python -m app.ml.train_risk_model
```

This will create the artifact directory if needed and save the model to `RISK_MODEL_PATH`.

## Storage and Integrity Behavior

### Runtime storage paths

- Encrypted records: `backend/storage/encrypted/`
- Quarantined records: `backend/storage/quarantined/`

### Integrity model

- Every uploaded record is encrypted before storage.
- The plaintext hash is stored in the database.
- Upload and security events are also written into the ledger.
- Download reads decrypt the file and re-verify the hash.
- Any mismatch or read failure triggers quarantine.

### Blockchain verification page

The admin verification page checks:

- whether each ledger block links to the previous block correctly
- whether the recomputed block hash matches the stored hash
- whether each stored medical file still decrypts to the expected SHA-256 value

## Operational Notes and Limitations

These points are important for realistic deployment expectations.

- The ledger is blockchain-style, but it is not a distributed blockchain network.
- Database schema creation uses `SQLAlchemy.create_all`; there is no migration framework such as Alembic in this repo.
- WebAuthn is configured for `localhost` by default. In production you must set `RP_ID` and `EXPECTED_ORIGIN` for your real domain and use HTTPS.
- Video calling uses WebRTC with a public Google STUN server. There is no TURN server configured, so some NAT/firewall scenarios may fail.
- File storage is local to the application container or machine. Production deployments should consider durable object storage, backup, and encryption-key rotation.
- The repo does not currently include automated tests.
- The current UI workflow gives doctors access based on approved appointments, while the API also exposes a separate explicit access-request mechanism through `/api/records/access/*`.
- The risk feature `new_device_24h` is computed by the scoring logic, but this codebase does not currently emit a dedicated `NEW_DEVICE_DETECTED` event by default.
- The first admin must be created intentionally. After that, additional admin registration is blocked.
- The ML artifact is not committed in this workspace. If it is missing, the application still works using heuristic scoring.

## Troubleshooting

### WebAuthn registration or login fails

- Make sure you are using a browser that supports WebAuthn.
- For local development, use `http://localhost:8000`.
- For non-localhost deployments, use HTTPS and update `RP_ID` and `EXPECTED_ORIGIN`.
- Ensure the device has a usable platform authenticator or passkey.

### Database connection errors

- Confirm PostgreSQL is running.
- Confirm the target database exists.
- Check `DATABASE_URL` in `backend/.env`.
- Re-run `python -m app.db.init_db` after fixing DB connectivity.

### Video room join or signaling errors

- Confirm login completed and a JWT exists in browser local storage.
- The doctor must create a room for the correct patient ID.
- Only the room's doctor and patient are allowed to join.
- Some networks may require a TURN server for reliable WebRTC connectivity.

### Record download returns an access error

- Patients can only access their own files.
- Doctor access in the dashboard depends on approved patient appointments.
- Lab assistants can only access reports associated with requests they completed.
- API record downloads may additionally depend on explicit record permissions.

### Record download returns a quarantine or blocked error

- The file may have been modified on disk.
- The encrypted file may be missing or unreadable.
- Decryption may have failed because the file contents changed.
- Check the admin blockchain verification page and risk events.

### Risk model file is missing

- This is acceptable for local use.
- The application will fall back to heuristic scoring automatically.
- Run `python -m app.ml.train_risk_model` if you want the ML model artifact.

## License

No license file is included in this repository. Treat the project as proprietary unless the owner adds an explicit license.
