def generate_explanation(
    process_name,
    pid,
    cpu_percent,
    memory_percent,
    anomaly_score
):
    """
    Generate a human-readable explanation
    for a detected anomaly.
    """

    explanation = f"""
ANOMALY DETECTED

Process:
{process_name}

PID:
{pid}

CPU Usage:
{cpu_percent:.2f}%

Memory Usage:
{memory_percent:.2f}%

Anomaly Score:
{anomaly_score:.4f}

Explanation:

The process was identified as anomalous by the
machine learning model because its observed
behavior differs from the patterns found in the
collected telemetry.

This does NOT automatically mean the process is
malicious. Further investigation is required.
"""

    return explanation

if __name__ == "__main__":

    result = generate_explanation(
        process_name="example.exe",
        pid=1234,
        cpu_percent=91.5,
        memory_percent=27.3,
        anomaly_score=-0.32
    )

    print(result)