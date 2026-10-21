# HoneyBank — How to Run

## 1) Setup
```bash
cd ~/Desktop/honeypot-banking
bash setup.sh
```

## 2) Start the system
### Option A: Recommended
```bash
cd ~/Desktop/honeypot-banking
./run.sh
```

### Option B: Direct run
```bash
cd ~/Desktop/honeypot-banking
./venv/bin/python main.py
```

### Option C: Docker
```bash
cd ~/Desktop/honeypot-banking
docker compose up -d --build
```

## 3) Open the apps
- Banking portal: http://localhost:8080
- Dashboard: http://localhost:5000
- SSH honeypot: localhost:2222

## 4) Stop it
If started in a terminal:
```bash
Ctrl + C
```

If using Docker:
```bash
cd ~/Desktop/honeypot-banking
docker compose down
```
