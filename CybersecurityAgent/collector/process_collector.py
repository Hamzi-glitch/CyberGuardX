import psutil
import time
import psycopg
from datetime import datetime


# ---------------------------------------
# Connect to PostgreSQL
# ---------------------------------------

connection = psycopg.connect(
    host="localhost",
    port=5432,
    dbname="cybersecurity_agent",
    user="postgres",
    password="hariri05"
)

cursor = connection.cursor()


print("=" * 80)
print("INTELLIGENT CYBERSECURITY AGENT - ACTIVITY COLLECTOR")
print("=" * 80)
print("Collecting process telemetry...")
print("Press CTRL+C to stop.\n")


try:

    while True:

        collection_time = datetime.now()

        # ---------------------------------------
        # Get current processes
        # ---------------------------------------

        processes = []

        for process in psutil.process_iter(
            ['pid', 'name', 'memory_percent']
        ):
            try:
                # First CPU measurement initializes psutil
                process.cpu_percent(interval=None)

                processes.append(process)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass


        # ---------------------------------------
        # Wait before taking second measurement
        # ---------------------------------------

        time.sleep(1)


        records_collected = 0


        # ---------------------------------------
        # Collect CPU + memory
        # ---------------------------------------

        for process in processes:

            try:

                cpu = process.cpu_percent(interval=None)

                memory = process.memory_percent()

                pid = process.pid

                name = process.name()


                # ---------------------------------------
                # Save telemetry to PostgreSQL
                # ---------------------------------------

                cursor.execute(
                    """
                    INSERT INTO process_activity
                    (timestamp, pid, process_name, cpu_percent, memory_percent)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        collection_time,
                        pid,
                        name,
                        cpu,
                        memory
                    )
                )

                records_collected += 1


            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass


        # ---------------------------------------
        # Commit records
        # ---------------------------------------

        connection.commit()


        print(
            f"[{collection_time}] "
            f"Collected {records_collected} process records."
        )


        # ---------------------------------------
        # Wait until next collection
        # ---------------------------------------

        time.sleep(5)


except KeyboardInterrupt:

    print("\nCollector stopped by user.")


finally:

    cursor.close()
    connection.close()

    print("Database connection closed.")