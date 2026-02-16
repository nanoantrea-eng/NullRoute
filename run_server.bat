@echo off
echo Starting NullRoute Backend...
if not exist node_modules (
    echo Installing dependencies...
    call npm install
)
echo Server running at http://localhost:3000
echo Opening browser...
start http://localhost:3000
call npm start
pause