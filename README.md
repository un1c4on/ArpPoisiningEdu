# ARP Spoofing & MITM Attack Simulation

## 📜 Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY. DO NOT USE THESE SCRIPTS FOR ILLEGAL ACTIVITIES.**

This project contains scripts to simulate a Man-in-the-Middle (MITM) attack using ARP Spoofing and DNS Spoofing. It is intended solely for educational use in a controlled lab environment to help network administrators and cybersecurity students understand the mechanics of this type of attack and how to defend against it.

The author is not responsible for any misuse or damage caused by these scripts. Unauthorized attacks on networks you do not own or have explicit permission to test are illegal.

---

## 📝 Description

This toolkit demonstrates a classic MITM attack. When the `attack.sh` script is executed, it:

1.  **Discovers network devices:** Scans the local network to find potential targets.
2.  **Performs ARP Spoofing:** Uses `arpspoof` to poison the ARP cache of a target machine and the network gateway, redirecting traffic through the attacker's machine.
3.  **Performs DNS Spoofing:** Uses `dnsmasq` to intercept DNS queries from the target. It resolves all domain names to the attacker's own IP address.
4.  **Serves a Fake Page:** Runs a local Python web server to serve a custom HTML page (`index.html`) to the victim for any HTTP request they make.

## 🚀 How to Use

1.  **Install Dependencies:** Ensure you have `dsniff` (which includes `arpspoof`), `arp-scan`, `python`, and `dnsmasq` installed.
    ```bash
    # On Arch Linux / Manjaro
    sudo pacman -S dsniff arp-scan python dnsmasq
    ```

2.  **Run the Attack Script:** Execute the main script with root privileges.
    ```bash
    sudo ./attack.sh
    ```

3.  **Follow the Prompts:** The script will display a list of devices on your network. Enter the IP address of the device you want to target.

4.  **Stop the Attack:** To stop the simulation and clean up all network changes (iptables, IP forwarding, etc.), press `CTRL+C` in the terminal where the script is running.
