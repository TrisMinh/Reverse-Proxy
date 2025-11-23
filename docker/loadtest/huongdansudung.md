

### 1. Đảm bảo Docker đang chạy

powershell
# Kiểm tra Docker
docker ps


### 2. Build Docker image (lần đầu tiên)

powershell
cd docker/loadtest
docker-compose build

### 3. Chạy test

powershell
.\run_tests.bat