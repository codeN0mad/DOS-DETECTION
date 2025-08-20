# 🚨 DoS Detector

*A simple Python-based system for detecting Denial of Service (DoS) attacks using Scapy.*

## 📌 Project Overview

This project implements a **DoS detection system** that monitors network traffic in real-time and identifies abnormal patterns indicative of a potential DoS attack.

It works by:

* Capturing packets with **Scapy**.
* Counting packets per IP within a **time window**.
* Comparing packet counts against a **threshold**.
* Logging and alerting when suspicious traffic is detected.

---

## 🎯 Objectives

* Monitor live traffic on a network interface.
* Detect abnormal spikes in packet flow.
* Alert when a potential **DoS attack** is identified.
* Maintain logs of detection events for analysis.

---

## ⚙️ Requirements

* **Python 3**
* **Scapy** library

Install Scapy:

```
pip install scapy
```

---

## 📂 Project Structure

```
├── dos_uneeq.py      # Main detection script
├── dos_log.txt       # Logs of alerts & packet counts
├── README.md         # Documentation
```

---

## ▶️ Usage

1. Clone this repository:

```
git clone https://github.com/your-username/dos-detector.git
cd dos-detector
```

2. Run the detection script with sudo/root privileges (required for packet sniffing):

```
sudo python3 dos_uneeq.py
```

3. By default, it monitors the **loopback interface (lo)**. You can modify it to use another interface in the code:

```python
sniff(iface="eth0", prn=detect_dos, store=False)
```

---

## 📊 Example Run




### ✅ Normal Traffic

```
[INFO] 127.0.0.1 sent 1 packets
```

### 🚨 Possible DoS Attack Detected

```
----- Checking packet counts -----
[ALERT] Possible DoS attack from 127.0.0.1 - 31684 packets in 10s
----------------------------------
```

---

## 🖼️ Screenshots

### DoS Detection in Action

![Detection Example](dos%20ss1.png)

### Generating High Traffic with Ping Flood

![Ping Flood](dos%20ss2.png)

---

## 🛡️ How It Works

* **Time Window:** 10 seconds
* **Threshold:** 100 packets (default)
* If any IP sends more than **100 packets in 10 seconds**, it raises an **ALERT**.
* Events are saved to `dos_log.txt`.

You can tune:

```python
time_window = 10      # seconds
threshold = 100       # packets
```

---

## ✅ Conclusion

This project demonstrates how to detect DoS attacks using **traffic monitoring** and **threshold-based anomaly detection**. While simple, it provides a foundation for building more advanced **Intrusion Detection Systems (IDS)**.

---
<img width="1647" height="1625" alt="dos ss1" src="https://github.com/user-attachments/assets/19afd082-ec2f-40c6-bfeb-b77ece5c7b68" />
<img width="1432" height="537" alt="dos ss2" src="https://github.com/user-attachments/assets/0f42d882-1d29-4cfa-b2a4-5cc07149d7d2" />


