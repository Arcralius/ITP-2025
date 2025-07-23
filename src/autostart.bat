@echo off
REM This script automates a sequence of tasks involving Python scripts and file operations.

REM --- Step 1: Run the collector script ---
echo [INFO] Starting the data collector...
start "Collector" python ./collector.py
echo [INFO] Collector script launched.
echo [INFO] Sleeping for 5 seconds...
timeout /t 5 /nobreak >nul
echo [INFO] Awake!

REM --- Step 2: Check for and create the download directory ---
echo [INFO] Checking for the './client_download' directory...
if not exist ".\\client_download" (
    echo [INFO] Directory not found. Creating it now...
    mkdir ".\\client_download"
) else (
    echo [INFO] Directory already exists.
)

REM --- Step 3: Copy the data file ---
REM This assumes there is at least one .txt file in the ./store directory.
echo [INFO] Copying data file from './store' to './client_download'...
copy ".\\store\\*.txt" ".\\client_download\\"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to copy the file. Make sure a .txt file exists in the 'store' directory.
    goto :eof
)

REM --- Step 4: Find the latest data file, read its first line, and run sensors ---
echo [INFO] Finding the data file with the largest number (latest date) in its name...

set "latest_file="
REM The 'dir /b /o-n' command lists files in bare format, sorted by name in reverse.
REM This makes the newest file (e.g., pwd_20250723.txt) the first in the list.
REM The 'for' loop captures only that first file and then jumps out.
for /f "delims=" %%F in ('dir /b /o-n ".\store\pwd_*.txt"') do (
    set "latest_file=.\store\%%F"
    goto :found_latest
)

:found_latest
if not defined latest_file (
    echo [ERROR] No 'pwd_*.txt' files found in the ./store directory.
    goto :eof
)

echo [INFO] Found latest file: %latest_file%
echo [INFO] Reading first line of data...

REM Read the first line from the identified file. The 'goto' acts like a 'break'.
for /f "usebackq delims=" %%a in ("%latest_file%") do (
    set "file_contents=%%a"
    goto :got_line
)

:got_line
REM Remove leading/trailing whitespace (basic method)
for /f "tokens=* delims= " %%a in ("%file_contents%") do set "file_contents=%%a"

if not defined file_contents (
    echo [ERROR] The first line in '%latest_file%' appears to be empty.
    goto :eof
)

echo [INFO] Running the Privacy Shield and HTTPs sensor with the collected data...
start "PrivacyShield" python privacyshield.py "%file_contents%"
start "https dns sensor" python https_sensor.py 2919e39a-fbc9-43f3-ba64-0cea356e3850 "%file_contents%"

REM --- Step 5: Done ---
echo [SUCCESS] Script finished successfully.