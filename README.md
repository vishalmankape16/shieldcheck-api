# ShieldCheck API

A FastAPI-based web application that checks websites for various security parameters and provides a safety assessment.

## Features

- Website security parameter validation
- SSL/TLS certificate checking
- Security headers inspection
- Content security policy validation
- HTTPS enforcement check
- Overall safety score calculation

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`

## API Documentation

Once the server is running, visit:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Endpoints

- `POST /check-website`: Check a website's security parameters
  - Request body: `{"url": "https://example.com"}`
  - Returns: Security assessment and recommendations 



## CURL
```curl -X POST "http://localhost:8000/check-website" -H "Content-Type: application/json" -d '{"url": "https://google.com"}'```