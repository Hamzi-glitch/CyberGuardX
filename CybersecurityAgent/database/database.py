import psycopg

connection = psycopg.connect(
    host="localhost",
    port=5432,
    dbname="cybersecurity_agent",
    user="postgres",
    password="hariri05"
)

print("Database connection successful!")

connection.close()