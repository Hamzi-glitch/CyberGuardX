import psycopg
import pandas as pd
from sklearn.ensemble import IsolationForest


# ============================================================
# INTELLIGENT CYBERSECURITY AGENT
# MACHINE LEARNING ANOMALY DETECTOR
# ============================================================


print("=" * 80)
print("INTELLIGENT CYBERSECURITY AGENT")
print("MACHINE LEARNING ANOMALY DETECTOR")
print("=" * 80)


# ============================================================
# 1. CONNECT TO POSTGRESQL
# ============================================================

print("\n[1/7] Connecting to PostgreSQL...")

connection = psycopg.connect(
    host="localhost",
    port=5432,
    dbname="cybersecurity_agent",
    user="postgres",
    password="hariri05"
)

print("Database connection successful!")


# ============================================================
# 2. GET TELEMETRY FROM DATABASE
# ============================================================

print("\n[2/7] Loading telemetry from database...")

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
    ORDER BY timestamp;
""")

rows = cursor.fetchall()

print(f"Retrieved {len(rows)} records.")


# ============================================================
# 3. CONVERT DATABASE DATA INTO PANDAS DATAFRAME
# ============================================================

print("\n[3/7] Creating DataFrame...")

columns = [
    "id",
    "timestamp",
    "pid",
    "process_name",
    "cpu_percent",
    "memory_percent"
]

df = pd.DataFrame(
    rows,
    columns=columns
)

print("DataFrame created successfully.")


# ============================================================
# 4. CLOSE DATABASE CONNECTION
# ============================================================

cursor.close()
connection.close()

print("Database connection closed.")


# ============================================================
# 5. CHECK DATA
# ============================================================

print("\n[4/7] Checking telemetry data...")

if len(df) < 10:

    print("ERROR: Not enough data for anomaly detection.")
    print(f"Current records: {len(df)}")
    print("Collect more telemetry before running the detector.")

    exit()


# Remove records where CPU or memory is missing

df = df.dropna(
    subset=[
        "cpu_percent",
        "memory_percent"
    ]
)

print(f"Records available for machine learning: {len(df)}")


# ============================================================
# 6. SELECT MACHINE LEARNING FEATURES
# ============================================================

print("\n[5/7] Selecting machine learning features...")

features = df[
    [
        "cpu_percent",
        "memory_percent"
    ]
]

print("Features being used:")

print(
    features.head(10).to_string(index=False)
)


# ============================================================
# 7. CREATE ISOLATION FOREST
# ============================================================

print("\n[6/7] Creating Isolation Forest model...")

model = IsolationForest(
    contamination=0.05,
    random_state=42
)

print("Isolation Forest created.")


# ============================================================
# 8. TRAIN MODEL
# ============================================================

print("\nTraining machine learning model...")

model.fit(features)

print("Model training completed!")


# ============================================================
# 9. DETECT ANOMALIES
# ============================================================

print("\n[7/7] Detecting anomalies...")

predictions = model.predict(features)

df["anomaly"] = predictions


# ============================================================
# 10. CONVERT ML OUTPUT TO HUMAN-READABLE STATUS
# ============================================================

df["status"] = df["anomaly"].map({
    1: "NORMAL",
    -1: "ANOMALY"
})


# ============================================================
# 11. GET ANOMALY SCORES
# ============================================================

df["anomaly_score"] = model.decision_function(
    features
)


# ============================================================
# 12. DISPLAY RESULTS
# ============================================================

print("\n")

print("=" * 120)
print("ANOMALY DETECTION RESULTS")
print("=" * 120)

print(
    df[
        [
            "timestamp",
            "pid",
            "process_name",
            "cpu_percent",
            "memory_percent",
            "anomaly_score",
            "status"
        ]
    ].to_string(index=False)
)


# ============================================================
# 13. SUMMARY
# ============================================================

normal_count = (
    df["status"] == "NORMAL"
).sum()

anomaly_count = (
    df["status"] == "ANOMALY"
).sum()


print("\n")

print("=" * 80)
print("SUMMARY")
print("=" * 80)

print(f"Total records : {len(df)}")
print(f"Normal        : {normal_count}")
print(f"Anomalies     : {anomaly_count}")


# ============================================================
# 14. SHOW ONLY ANOMALIES
# ============================================================

print("\n")

print("=" * 100)
print("DETECTED ANOMALIES")
print("=" * 100)


anomalies = df[
    df["status"] == "ANOMALY"
]


if len(anomalies) == 0:

    print("No anomalies detected.")

else:

    print(
        anomalies[
            [
                "timestamp",
                "pid",
                "process_name",
                "cpu_percent",
                "memory_percent",
                "anomaly_score"
            ]
        ].to_string(index=False)
    )


# ============================================================
# 15. FINISHED
# ============================================================

print("\n")

print("=" * 80)
print("ANOMALY DETECTION COMPLETE")
print("=" * 80)