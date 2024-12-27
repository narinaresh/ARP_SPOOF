# ARP Spoof Detector
This project is a C-based implementation of an ARP (Address Resolution Protocol) spoof detection tool. 
It monitors the network for suspicious ARP activity and alerts the user to potential ARP spoofing attacks. 
ARP spoofing attacks can compromise the integrity of a network by redirecting traffic or enabling man-in-the-middle attacks.

## Features

- Detects ARP spoofing attacks in real-time.
- Captures and analyzes ARP packets using the `pcap` library.
- Logs suspicious activity for further inspection.

## Requirements

To build and run this project, you need the following:
- A C compiler (e.g., GCC).
- Development headers for `libpcap` (e.g., `libpcap-dev` on Linux).
- A network interface with monitoring permissions (e.g., `eth0`).

## Setup and Installation

1. Install the required dependencies on your system:

   ```bash
   sudo apt-get install libpcap-dev
   ```

2. Clone the repository or download the source code:

   ```bash
   git clone https://github.com/narinaresh/ARP_SPOOF.git
   cd ARP_SPOOF
   ```

3. Compile the code using GCC:

   ```bash
   gcc -o arpsniffer.c -lpcap -o arpspoofdetector
   ```


4. Run the executable with superuser privileges (required for network operations):

   ```bash
   sudo ./arpspoofdetector 
   ```
 To start decctect 

 ```bash
sudo ./arpsoofdetector -i <interface>
```

## Usage

When executed, the program will:
   - Monitor ARP traffic on the specified interface.
   - Alert the user to potential ARP spoofing attacks.

## How It Works

1. **Packet Capture**: The program uses `libpcap` to capture ARP packets in real-time.
2. **Analysis**: Each ARP packet is inspected to detect anomalies such as duplicate IP-to-MAC mappings.
3. **Alerting**: If a potential ARP spoofing attack is detected, a warning message is displayed.

## Example Output

```
Monitoring ARP traffic on eth0...
[ALERT] Potential ARP spoofing detected! IP 192.168.1.1 has conflicting MAC addresses.
```

## Contributing

Contributions are welcome! If you find any issues or want to add features, feel free to submit a pull request or open an issue.

## Disclaimer

This tool is intended for educational and ethical purposes only. Unauthorized use on networks without permission is prohibited.

