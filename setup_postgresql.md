# PostgreSQL Setup Instructions

## Step 1: Install PostgreSQL

### Option A: Download and Install
1. Download PostgreSQL from: https://www.postgresql.org/download/windows/
2. Run the installer
3. During installation:
   - Remember the password you set for the `postgres` user (default is often `postgres`)
   - Note the port (default is `5432`)
   - Complete the installation

### Option B: Using Chocolatey (if installed)
```powershell
choco install postgresql
```

## Step 2: Start PostgreSQL Service

After installation, PostgreSQL should start automatically. If not:

```powershell
# Start PostgreSQL service
Start-Service postgresql-x64-<version>
# Or check service name:
Get-Service -Name postgresql*
```

## Step 3: Create Database

Once PostgreSQL is installed and running, open a command prompt or PowerShell and run:

```powershell
# Navigate to PostgreSQL bin directory (adjust version number)
cd "C:\Program Files\PostgreSQL\<version>\bin"

# Create database (you'll be prompted for postgres user password)
.\psql.exe -U postgres -c "CREATE DATABASE skykeen_db;"
```

Or use pgAdmin (GUI tool that comes with PostgreSQL):
1. Open pgAdmin
2. Connect to PostgreSQL server
3. Right-click on "Databases" → "Create" → "Database"
4. Name it `skykeen_db`
5. Click "Save"

## Step 4: Update .env File

The `.env` file has been created with default values. Update the password if you set a different one during installation:

```env
DB_PASSWORD=your_actual_postgres_password
```

## Step 5: Run Migrations

Once PostgreSQL is set up and the database is created:

```bash
python manage.py migrate
```

## Verify Connection

Test the connection:
```bash
python manage.py dbshell
```

If it connects successfully, you're all set!

