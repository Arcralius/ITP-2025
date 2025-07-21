@echo off
REM This script automates a sequence of tasks involving Python scripts and file operations.

REM --- Step 1: Run the collector script ---
echo [INFO] Starting the data collector...
start "Collector" python ./collector.py
echo [INFO] Collector script launched.

REM --- Step 2: Wait for 5 seconds ---
echo [INFO] Waiting for 5 seconds to allow data collection...
timeout /t 5 /nobreak > nul

REM --- Step 3: Check for and create the download directory ---
echo [INFO] Checking for the './client_download' directory...
if not exist ".\\client_download" (
    echo [INFO] Directory not found. Creating it now...
    mkdir ".\\client_download"
) else (
    echo [INFO] Directory already exists.
)

REM --- Step 4: Copy the data file ---
REM This assumes there is at least one .txt file in the ./store directory.
echo [INFO] Copying data file from './store' to './client_download'...
copy ".\\store\\*.txt" ".\\client_download\\"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to copy the file. Make sure a .txt file exists in the 'store' directory.
    goto :eof
)

REM --- Step 5: Run the privacy shield script ---
echo [INFO] Running the privacy shield script...
start "PrivacyShield" python privacyshield.py

REM --- Step 6: Read file contents and run the HTTP sensor ---
echo [INFO] Reading data from the store file to send to the sensor...
set "FILE_TO_READ="
for %%F in (.\\store\\*.txt) do (
    set "FILE_TO_READ=%%F"
    goto :found_file
)

:found_file
if not defined FILE_TO_READ (
    echo [ERROR] No .txt file found in the ./store directory.
    goto :eof
)

REM Read the entire content of the file into a variable.
setlocal enabledelayedexpansion
set "file_contents="
for /f "usebackq delims=" %%a in ("%FILE_TO_READ%") do (
    set "file_contents=!file_contents! %%a"
)
endlocal & set "file_contents=%file_contents:~1%"

if not defined file_contents (
    echo [ERROR] The file at '%FILE_TO_READ%' appears to be empty.
    goto :eof
)

echo [INFO] Running the HTTP sensor with the collected data...
python https_sensor.py 2919e39a-fbc9-43f3-ba64-0cea356e3850 "%file_contents%"

REM --- Step 7: Terminate background processes ---
echo [INFO] Cleaning up background processes...
taskkill /F /FI "WINDOWTITLE eq Collector" > nul 2>&1
taskkill /F /FI "WINDOWTITLE eq PrivacyShield" > nul 2>&1
echo [INFO] Cleanup complete.

echo [SUCCESS] Script finished successfully.

:eof
REM Use 'pause' if you want the window to stay open after the script finishes.
REM pause
