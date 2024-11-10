# Advanced Recon and Exfiltration Script

## Overview
This project contains a PowerShell-based BadUSB payload designed for advanced recon of a target PC. The script gathers detailed system information, including usernames, emails, Wi-Fi passwords, and more. The gathered data is exfiltrated via a Discord webhook.

### **Features:**
- Collects user information (username, email).
- Retrieves system information (OS, CPU, RAM, BIOS).
- Extracts saved Wi-Fi passwords.
- Attempts to gather geolocation data.
- Exfiltrates data to a Discord webhook.
- Cleans up traces after execution.

## **Usage:**

### **1. Setup:**
- Clone the repository:
  ```bash
  git clone https://github.com/yourusername/advanced-recon-script.git
