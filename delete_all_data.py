import mysql.connector

# Database connection configuration
config = {
    'user': 'farmdat1_Wasomi2',
    'password': 'r69P4hdMRtRr',
    'host': '192.254.250.180',
    'database': 'farmdat1_mysql_farmdata',
}

try:
    # Establish a database connection
    conn = mysql.connector.connect(**config)
    cursor = conn.cursor()

    # Disable foreign key checks
    cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")

    # Retrieve all table names from the specified database
    cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = %s;", (config['database'],))
    tables = cursor.fetchall()

    # Iterate through the tables and delete all data
    for (table_name,) in tables:
        cursor.execute(f"DELETE FROM {table_name};") 

    # Commit the changes
    conn.commit()

    print("All data deleted from all tables successfully.")

except mysql.connector.Error as err:
    print(f"Error: {err}")

finally:
    # Clean up
    cursor.execute("SET FOREIGN_KEY_CHECKS = 1;") 
    cursor.close()
    conn.close()
