@echo off
REM This script automates a sequence of tasks involving Python scripts and file operations.

REM --- Step 1: Run the collector script ---
echo [INFO] Starting the data collector...
start "Collector" python ./collector.py
echo [INFO] Collector script launched.
echo Sleeping for 5 seconds...
timeout /t 5 /nobreak >nul
echo Awake!

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

REM --- Step 4: Read the first line from the store file and run the Privacy Shield and HTTPs sensor ---
echo [INFO] Reading first line of data from the store file...

set "FILE_TO_READ="
for %%F in (.\store\*.txt) do (
    set "FILE_TO_READ=%%F"
    goto :found_file
)

:found_file
if not defined FILE_TO_READ (
    echo [ERROR] No .txt file found in the ./store directory.
    goto :eof
)

setlocal enabledelayedexpansion
set "file_contents="
for /f "usebackq delims=" %%a in ("%FILE_TO_READ%") do (
    set "file_contents=%%a"
    goto :got_line
)

:got_line
endlocal & set "file_contents=%file_contents:~0,4096%"

REM Remove leading/trailing whitespace (basic method)
for /f "tokens=* delims= " %%a in ("%file_contents%") do set "file_contents=%%a"

if not defined file_contents (
    echo [ERROR] The first line in '%FILE_TO_READ%' appears to be empty.
    goto :eof
)

echo [INFO] Running the Privacy Shield and HTTPs sensor with the collected data...
start "PrivacyShield" python privacyshield.py "%file_contents%"
start "https dns sensor" python https_sensor.py 2919e39a-fbc9-43f3-ba64-0cea356e3850 "%file_contents%"

REM --- Step 5: Done ---

echo [SUCCESS] Script finished successfully.