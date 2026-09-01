import psycopg

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(
    title="Intelligent Cybersecurity Agent",
    description="Cybersecurity monitoring and anomaly detection API",
    version="1.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():

    return psycopg.connect(
        host="localhost",
        port=5432,
        dbname="cybersecurity_agent",
        user="postgres",
        password="hariri05"
    )


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "message": "Cybersecurity Agent API is running"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health_check():

    return {
        "status": "healthy"
    }


# ============================================================
# GET RECENT PROCESS ACTIVITY
# ============================================================

@app.get("/processes")
def get_processes():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            pid,
            process_name,
            cpu_percent,
            memory_percent
        FROM process_activity
        ORDER BY timestamp DESC
        LIMIT 100;
    """)

    rows = cursor.fetchall()

    cursor.close()
    connection.close()


    processes = []

    for row in rows:

        processes.append({
            "id": row[0],
            "timestamp": row[1],
            "pid": row[2],
            "process_name": row[3],
            "cpu_percent": row[4],
            "memory_percent": row[5]
        })


    return processes