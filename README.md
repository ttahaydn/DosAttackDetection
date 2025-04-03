
# 🛡️ DoS Attack Detection Using Deterministic Finite Automata (DFA)

This project presents a method for detecting SYN Flood DoS (Denial-of-Service) attacks using Time-Dependent Finite Automata (TDFA). It combines real-time packet analysis with a formally defined DFA represented in XML.

## 📌 Project Objective

To develop a DFA-based detection system that identifies SYN flood patterns in network traffic using:

- A predefined DFA structure (in XML format)
- Real-time packet sniffing using Scapy
- Evaluation of time intervals between TCP SYN packets

## 📁 Project Structure

```
.
├── Codes.py         # Python script for packet analysis and DFA evaluation
├── dfa.xml          # XML definition of the DFA structure
├── Report.pdf       # Final project report explaining background, design, and results
```

## 📥 How It Works

1. **XML DFA Definition (`dfa.xml`)**:
   - Defines states: `s0` (start), `s1` (critical), `s2` (attack/accept state)
   - Alphabet: `a` (SYN packets > 10), `b` (≤10), `c` (<0.1s delay), `d` (≥0.1s)
   - Includes transitions between states depending on packet behavior

2. **Python Packet Analysis (`Codes.py`)**:
   - Loads the DFA structure from `dfa.xml`
   - Monitors live network traffic using Scapy
   - Analyzes TCP packets with SYN flags
   - Detects potential DoS behavior based on packet frequency and timing
   - Triggers an alert if the DFA reaches the accepting state

## ⚙️ Requirements

- Python 3.x
- Scapy
```bash
pip install scapy
```

## ▶️ Running the Application

1. Connect to the network you want to monitor.
2. Run the Python script and enter your interface name (e.g., `eth0`, `wlan0`).
```bash
python Codes.py
```
3. If a SYN flood pattern is detected, packet details will be printed and an alert message will be shown.

## 🧠 TDFA Overview

This TDFA model is used to detect fast SYN flood attacks:

- `s0` — Start
- `s1` — Critical (SYN count > 10)
- `s2` — Attack Detected (short interval between packets)

Transitions:
- `a`: SYN count > 10 → `s0` to `s1`
- `c`: Time diff < 0.1s → `s1` to `s2` (attack state)
- `b` and `d`: For other transitions to avoid false positives

## 👨‍💻 Authors

- Umut Öztürk  [Github](https://github.com/umtoztrk)
- Abdullah Taha Aydın  
- Atakan Berber [Github](https://github.com/aetherr07)   

> Eskisehir Osmangazi University – Computer Engineering Department  
> Project for Formal Languages and Automata – Spring 2023–2024

## 📄 Report

For detailed background, methodology, visuals, and DFA diagrams, see the [`Report.pdf`](./Report.pdf).

