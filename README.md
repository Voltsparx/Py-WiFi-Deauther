# Py-WiFi-Deauther

**Py-WiFi-Deauther** is an ethical WiFi security testing tool for educational and authorized penetration testing purposes. It allows you to perform deauthentication attacks and beacon flooding to test the robustness of wireless networks.

## Features

- **Deauthentication Attack:** Disconnect clients from a target WiFi network.
- **Beacon Flood:** Create multiple fake access points to flood the area.
- **Network Scanning:** Discover nearby WiFi networks and select targets interactively.
- **Monitor Mode Management:** Automatically set your wireless interface to monitor mode.
- **Rich UI (optional):** Enhanced terminal output using [Rich](https://github.com/Textualize/rich) if installed.

## Usage

> **Warning:**  
> This tool is for educational and ethical testing purposes only.  
> Unauthorized use against networks you do not own or have explicit permission to test is illegal.

### Requirements

- Python 3.x
- [Scapy](https://scapy.net/)
- [netifaces](https://pypi.org/project/netifaces/)
- `iwconfig` and `ifconfig` (Linux wireless tools)
- (Optional) [Rich](https://github.com/Textualize/rich) for enhanced UI

### Installation

```sh
sudo apt-get install wireless-tools
pip install scapy netifaces rich
```

### Running

Run the tool with root privileges:

```sh
sudo python3 py-wifi-deauther.py
```

Follow the interactive prompts to:

1. Select your wireless interface.
2. Scan and choose a target network.
3. Select attack type (Deauth or Beacon Flood).
4. Set attack duration and confirm.

## Ethical Notice

This tool is intended for use in controlled environments where you have explicit permission.  
The author assumes no liability for misuse.

## License

MIT License

## Author

- voltsparx  
- Contact: voltsparx@204
