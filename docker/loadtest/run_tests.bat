@echo off
REM Windows batch script to run load tests with Docker

echo === Reverse Proxy Load Testing Suite ===
echo.

REM Check if Docker is running
docker ps >nul 2>&1
if errorlevel 1 (
    echo Error: Docker is not running
    echo Please start Docker Desktop and try again
    pause
    exit /b 1
)

REM Check if docker-compose exists
docker-compose version >nul 2>&1
if errorlevel 1 (
    echo Error: docker-compose not found
    echo Please install Docker Compose
    pause
    exit /b 1
)

REM Build image if not exists
docker images | findstr "reverse-proxy-loadtest" >nul
if errorlevel 1 (
    echo Building loadtest image...
    docker-compose build
)

echo.
echo Select test to run:
echo 1. wrk - HTTP Benchmarking ^(Recommended^)
echo 2. Apache Bench ^(ab^) - Classic tool
echo 3. hey - Modern Go-based tool
echo 4. Cache Performance Test
echo 5. Run all tests
echo.

set /p choice="Enter choice (1-5): "

if "%choice%"=="1" (
    echo Running wrk test...
    docker-compose run --rm loadtest ./wrk_test.sh
) else if "%choice%"=="2" (
    echo Running Apache Bench test...
    docker-compose run --rm loadtest ./ab_test.sh
) else if "%choice%"=="3" (
    echo Running hey test...
    docker-compose run --rm loadtest ./hey_test.sh
) else if "%choice%"=="4" (
    echo Running cache performance test...
    docker-compose run --rm loadtest ./cache_test.sh
) else if "%choice%"=="5" (
    echo Running all tests...
    echo.
    echo === Test 1: wrk ===
    docker-compose run --rm loadtest ./wrk_test.sh
    echo.
    echo === Test 2: Apache Bench ===
    docker-compose run --rm loadtest ./ab_test.sh
    echo.
    echo === Test 3: hey ===
    docker-compose run --rm loadtest ./hey_test.sh
    echo.
    echo === Test 4: Cache Performance ===
    docker-compose run --rm loadtest ./cache_test.sh
) else (
    echo Invalid choice
    pause
    exit /b 1
)

echo.
echo === Test Complete ===
pause





