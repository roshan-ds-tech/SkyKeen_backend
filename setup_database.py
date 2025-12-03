"""
Script to create PostgreSQL database after installation.
Run this after PostgreSQL is installed and the service is running.
"""
import os
import sys
import psycopg2
from psycopg2 import sql

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

DB_NAME = os.getenv('DB_NAME', 'skykeen_db')
DB_USER = os.getenv('DB_USER', 'postgres')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'postgres')
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = os.getenv('DB_PORT', '5432')

def create_database():
    """Create the database if it doesn't exist."""
    try:
        # Connect to PostgreSQL server (default 'postgres' database)
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database='postgres'  # Connect to default database
        )
        conn.autocommit = True
        cursor = conn.cursor()
        
        # Check if database exists
        cursor.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s",
            (DB_NAME,)
        )
        exists = cursor.fetchone()
        
        if exists:
            print(f"Database '{DB_NAME}' already exists.")
        else:
            # Create database
            cursor.execute(
                sql.SQL("CREATE DATABASE {}").format(
                    sql.Identifier(DB_NAME)
                )
            )
            print(f"Database '{DB_NAME}' created successfully!")
        
        cursor.close()
        conn.close()
        return True
        
    except psycopg2.OperationalError as e:
        print(f"Error connecting to PostgreSQL: {e}")
        print("\nPlease ensure:")
        print("1. PostgreSQL is installed")
        print("2. PostgreSQL service is running")
        print("3. Database credentials in .env are correct")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == '__main__':
    print("Setting up PostgreSQL database...")
    print(f"Database name: {DB_NAME}")
    print(f"User: {DB_USER}")
    print(f"Host: {DB_HOST}:{DB_PORT}\n")
    
    if create_database():
        print("\n✅ Database setup complete!")
        print("Now run: python manage.py migrate")
    else:
        print("\n❌ Database setup failed. Please check the errors above.")
        sys.exit(1)

