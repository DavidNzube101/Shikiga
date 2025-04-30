# Shikiga - Solana Attack Detection API

Shikiga is a Python-based RESTful service designed to detect two common malicious behaviors on the Solana blockchain:

1. **Dusting Attacks**: Unsolicited small token transfers sent to many accounts to link or deanonymize wallets.  
2. **Address Poisoning**: Transfers from lookalike addresses or with misleading metadata that corrupt users’ address books and trick them into future scams.

---

## Table of Contents

- [Shikiga - Solana Attack Detection API](#shikiga---solana-attack-detection-api)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [API Endpoints](#api-endpoints)
    - [1. Analyze a Transaction](#1-analyze-a-transaction)
    - [2. Analyze an Account](#2-analyze-an-account)
    - [3. Health Check](#3-health-check)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
    - [With Docker](#with-docker)
    - [Manual Setup](#manual-setup)
  - [Configuration](#configuration)
  - [Project Structure](#project-structure)
  - [Usage Examples](#usage-examples)
  - [Testing](#testing)
  - [Client SDK](#client-sdk)
  - [License](#license)

---

## Features

- **Heuristic Detection**  
  - Configurable dust-value thresholds  
  - Rapid-transfer frequency analysis  
  - Memo-pattern recognition  
  - Address-similarity checks

- **Machine Learning Anomaly Detection**  
  - Optional pre-trained model (`anomaly_detector.pkl`)  
  - Probabilistic scoring for suspicious transactions

- **Reputation Management**  
  - In-memory or Redis-backed sender reputation store  
  - History-based scoring to reduce false positives

- **Analytics**  
  - Single-transaction scoring  
  - Account-history summarization  
  - Detailed reasoning for each flag

- **Extensible & Open Source**  
  - MIT-licensed, modular detectors  
  - Clear hooks for custom detection logic

---

## API Endpoints

### 1. Analyze a Transaction

```http
POST /v1/analyze/transaction HTTP/1.1
Content-Type: application/json
```

**Request Body**:

```json
{
  "transaction": "<base64-encoded-transaction>",
  "slot": 175000000   # (optional) block slot number
}
```

**Response**:

```json
{
  "score": 0.87,
  "labels": ["dusting"],
  "reasons": [
    "value_below_threshold",
    "high_sender_frequency"
  ]
}
```

---

### 2. Analyze an Account

```http
POST /v1/analyze/account HTTP/1.1
Content-Type: application/json
```

**Request Body**:

```json
{
  "address": "<Solana-account-address>",
  "start_slot": 174950000,   # (optional)
  "end_slot": 175000000      # (optional)
}
```

**Response**:

```json
{
  "overall_score": 0.65,
  "episodes": [
    {
      "txSig": "transaction-signature",
      "label": "poisoning",
      "slot": 174960123,
      "score": 0.78
    }
  ]
}
```

---

### 3. Health Check

```http
GET /v1/health HTTP/1.1
```

**Response**:

```json
{
  "status": "ok",
  "version": "1.0.0"
}
```

---

## Prerequisites

- Python 3.9 or higher  
- MongoDB (default: `mongodb://localhost:27017`)  
- Redis (default: `redis://localhost:6379`)  
- (Optional) Pre-trained anomaly detection model: `models/anomaly_detector.pkl`

---

## Installation

### With Docker

1. Clone the repo:

   ```bash
   git clone https://github.com/DavidNzube101/Shikiga.git
   cd Shikiga
   ```

2. Copy or train your ML model:

   ```bash
   mkdir -p models
   cp /path/to/anomaly_detector.pkl models/
   ```

3. Launch services:

   ```bash
   docker-compose up -d
   ```

4. Visit `http://localhost:8000/docs` for interactive API docs.

---

### Manual Setup

1. Clone and navigate:

   ```bash
   git clone https://github.com/DavidNzube101/Shikiga.git
   cd Shikiga
   python -m venv venv
   source venv/bin/activate    # Windows: venv\Scripts\activate
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Start MongoDB and Redis, or configure via environment variables.
4. Place ML model (optional):

   ```bash
   cp /path/to/anomaly_detector.pkl models/
   ```

5. Run the API:

   ```bash
   uvicorn app.main:app --reload
   ```

---

## Configuration

Configure via environment variables or a `.env` file in the project root:

| Variable            | Default                                  | Description                                 |
|---------------------|------------------------------------------|---------------------------------------------|
| `MONGODB_URL`       | `mongodb://localhost:27017`              | MongoDB connection URI                      |
| `DATABASE_NAME`     | `solana_attack_detection`                | MongoDB database name                       |
| `REDIS_URL`         | `redis://localhost:6379`                 | Redis connection URI                        |
| `DUST_THRESHOLD`    | `0.01`                                   | SOL amount below which is considered dust   |
| `MODEL_PATH`        | `models/anomaly_detector.pkl`            | Path to the ML model file                  |

---

## Project Structure

``` bash
Shikiga/
├── app/
│   ├── main.py               # FastAPI entrypoint
│   ├── api/                  # Endpoint definitions
│   ├── core/                 # Business logic & detectors
│   │   ├── config.py         # App settings loader
│   │   ├── detectors/        # Heuristic & ML detectors
│   │   └── reputation/       # Sender reputation store
│   └── db/                   # Database session management
├── models/                   # ML model files
├── tests/                    # Unit and integration tests
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── ReadMe.md                 # This file
```

---

## Usage Examples

Use cURL or any HTTP client:

```bash
# Transaction analysis
curl -X POST http://localhost:8000/v1/analyze/transaction \
  -H "Content-Type: application/json" \
  -d '{"transaction":"<base64>"}'

# Account analysis
curl -X POST http://localhost:8000/v1/analyze/account \
  -H "Content-Type: application/json" \
  -d '{"address":"<address>","start_slot":0}'
```

---

## Testing

Run the full test suite with:

```bash
pytest
```

---

## Client SDK

A simple Python client is provided in `client.py`. Example usage:

```python
from client import SolanaAttackDetectionClient

client = SolanaAttackDetectionClient("http://localhost:8000")
result = client.analyze_transaction(raw_tx_data)
print(result)
```

---

## License

This project is open source under the MIT License. See [LICENSE](LICENSE) for details.
