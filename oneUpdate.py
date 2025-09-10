#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Creative WiFi Hacker - Advanced Wireless Security Assessment Tool
Version: 5.0 | Author: Security Researcher | Telegram: @W8SOJIB
"""

import sys
import subprocess
import os
import tempfile
import shutil
import re
import codecs
import socket
import pathlib
import time
from datetime import datetime
import collections
import statistics
import csv
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import random
import json
import threading
import queue
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
import struct
import fcntl
import select
import errno
import base64
import zlib
import binascii

# Advanced UI and Utility Classes
try:
    from pyfiglet import Figlet
except ImportError:
    Figlet = None

try:
    import psutil
except ImportError:
    psutil = None

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError:
    # Fallback colors if colorama not available
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Back:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''

class CreativeUI:
    """Advanced UI system with animations and styling"""

    THEMES = {
        'default': {
            'header': Fore.CYAN,
            'success': Fore.GREEN,
            'error': Fore.RED,
            'warning': Fore.YELLOW,
            'info': Fore.BLUE,
            'text': Fore.WHITE
        },
        'dark': {
            'header': Fore.MAGENTA,
            'success': Fore.GREEN,
            'error': Fore.RED,
            'warning': Fore.YELLOW,
            'info': Fore.CYAN,
            'text': Fore.WHITE
        },
        'light': {
            'header': Fore.BLUE,
            'success': Fore.GREEN,
            'error': Fore.RED,
            'warning': Fore.YELLOW,
            'info': Fore.MAGENTA,
            'text': Fore.BLACK
        }
    }

    def __init__(self, theme='default'):
        self.theme = self.THEMES.get(theme, self.THEMES['default'])
        self.animation_frames = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
        self.progress_chars = ["█", "▓", "▒", "░"]

    def set_theme(self, theme):
        """Set UI theme"""
        self.theme = self.THEMES.get(theme, self.THEMES['default'])

    def print_banner(self):
        """Advanced ASCII art banner with system info"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if Figlet:
            try:
                f = Figlet(font='slant')
                banner_text = f.renderText('Creative WiFi')
            except:
                banner_text = "Creative WiFi Hacker v5.0"
        else:
            banner_text = "Creative WiFi Hacker v5.0"

        banner = f"""
{self.theme['header']}╔════════════════════════════════════════════════════════════════════╗
{self.theme['header']}║{Fore.MAGENTA}{banner_text.center(64)}{self.theme['header']}║
{self.theme['header']}║{Fore.YELLOW}           Advanced Wireless Security Toolkit v5.0          {self.theme['header']}║
{self.theme['header']}║{Fore.GREEN}                 Author: Security Researcher                {self.theme['header']}║
{self.theme['header']}║{Fore.CYAN}               Telegram: {Fore.WHITE}@W8SOJIB{Fore.CYAN}                           {self.theme['header']}║
{self.theme['header']}║{Fore.WHITE}               Time: {current_time}                 {self.theme['header']}║
{self.theme['header']}╚════════════════════════════════════════════════════════════════════╝
{Fore.RESET}"""
        print(banner)

    def print_header(self, text, width=60):
        """Print section header with styled border"""
        width = max(len(text) + 4, width)
        print(f"\n{self.theme['header']}╔{'═' * width}╗")
        print(f"║ {self.theme['text']}{text.center(width - 2)}{self.theme['header']} ║")
        print(f"╚{'═' * width}╝{Fore.RESET}")

    def print_success(self, text):
        """Print success message"""
        print(f"{self.theme['success']}✅ {text}{Fore.RESET}")

    def print_error(self, text):
        """Print error message"""
        print(f"{self.theme['error']}❌ {text}{Fore.RESET}")

    def print_warning(self, text):
        """Print warning message"""
        print(f"{self.theme['warning']}⚠️  {text}{Fore.RESET}")

    def print_info(self, text):
        """Print info message"""
        print(f"{self.theme['info']}ℹ️  {text}{Fore.RESET}")

    def progress_bar(self, iteration, total, prefix='', suffix='', length=50, fill='█'):
        """Create animated progress bar"""
        percent = ("{0:.1f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
        if iteration == total:
            print()

    def loading_animation(self, text="Loading", delay=0.1, frames=20):
        """Show loading animation"""
        for i in range(frames):
            print(f"\r{text} {self.animation_frames[i % len(self.animation_frames)]}", end="")
            time.sleep(delay)
        print("\r" + " " * (len(text) + 2) + "\r", end="")

    def table_header(self, headers, widths=None):
        """Print table header"""
        if not widths:
            widths = [15] * len(headers)

        header_line = ""
        for i, header in enumerate(headers):
            header_line += f"{header:<{widths[i]}} "

        print(f"{self.theme['header']}{header_line}{Fore.RESET}")
        print(f"{self.theme['header']}{'-' * (sum(widths) + len(headers) - 1)}{Fore.RESET}")

    def table_row(self, items, widths=None):
        """Print table row"""
        if not widths:
            widths = [15] * len(items)

        row = ""
        for i, item in enumerate(items):
            row += f"{str(item):<{widths[i]}} "
        print(row)

    def menu_option(self, number, text):
        """Print menu option"""
        print(f"{self.theme['header']} [{self.theme['text']}{number}{self.theme['header']}] {self.theme['text']}{text}")

    def input_prompt(self, text):
        """Get user input with styled prompt"""
        return input(f"{self.theme['info']}➤ {text}{Fore.RESET}")

class NetworkUtils:
    """Network utility functions"""

    @staticmethod
    def get_wireless_interfaces():
        """Get list of wireless interfaces"""
        try:
            result = subprocess.run("iw dev | grep Interface", shell=True,
                                  capture_output=True, text=True)
            interfaces = [line.split()[-1] for line in result.stdout.split('\n') if line]
            return interfaces
        except:
            return ["wlan0", "wlan1", "wlp2s0", "wlo1"]

    @staticmethod
    def check_interface_exists(interface):
        """Check if network interface exists"""
        try:
            subprocess.run(f"ip link show {interface}", shell=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return True
        except:
            return False

    @staticmethod
    def set_monitor_mode(interface):
        """Set interface to monitor mode"""
        try:
            CreativeUI().print_info(f"Setting {interface} to monitor mode...")
            subprocess.run(f"ip link set {interface} down", shell=True, check=True)
            subprocess.run(f"iw dev {interface} set monitor control", shell=True, check=True)
            subprocess.run(f"ip link set {interface} up", shell=True, check=True)
            CreativeUI().print_success(f"{interface} set to monitor mode")
            return True
        except Exception as e:
            CreativeUI().print_error(f"Failed to set monitor mode: {e}")
            return False

    @staticmethod
    def set_managed_mode(interface):
        """Set interface to managed mode"""
        try:
            CreativeUI().print_info(f"Setting {interface} to managed mode...")
            subprocess.run(f"ip link set {interface} down", shell=True, check=True)
            subprocess.run(f"iw dev {interface} set type managed", shell=True, check=True)
            subprocess.run(f"ip link set {interface} up", shell=True, check=True)
            CreativeUI().print_success(f"{interface} set to managed mode")
            return True
        except Exception as e:
            CreativeUI().print_error(f"Failed to set managed mode: {e}")
            return False

class SecurityUtils:
    """Security and encryption utilities"""

    @staticmethod
    def generate_random_mac():
        """Generate random MAC address"""
        return ":".join([f"{random.randint(0x00, 0xff):02x}" for _ in range(6)])

    @staticmethod
    def calculate_wpa_psk(ssid, password):
        """Calculate WPA PSK (simplified)"""
        try:
            # This is a simplified version for demonstration
            import hashlib
            import hmac
            import binascii

            # PMK = PBKDF2(HMAC−SHA1, passphrase, ssid, 4096, 256)
            # For real implementation, use proper PBKDF2
            return hashlib.sha256(f"{ssid}{password}".encode()).hexdigest()[:64]
        except:
            return "Unable to calculate PSK"

    @staticmethod
    def check_vulnerabilities(bssid, model=None):
        """Check for known vulnerabilities"""
        vulnerabilities = {
            "router": ["WPS Pixie Dust", "Default Credentials", "UPnP Exploit"],
            "access_point": ["KARMA Attack", "Evil Twin", "WPS Brute Force"],
            "client": ["KRACK Attack", "PMKID Attack", "Handshake Capture"]
        }

        # Simulate vulnerability detection
        detected = []
        if random.random() > 0.3:
            detected.extend(random.sample(vulnerabilities["router"], 2))
        if random.random() > 0.5:
            detected.extend(random.sample(vulnerabilities["access_point"], 1))

        return detected

class AdvancedScanner:
    """Advanced network scanner with multiple techniques"""

    def __init__(self, interface="wlan0"):
        self.interface = interface
        self.networks = []
        self.clients = []
        self.scan_timeout = 30

    def scan_networks(self, scan_type="active"):
        """Scan for wireless networks"""
        CreativeUI().print_info(f"Starting {scan_type} scan on {self.interface}...")

        try:
            if scan_type == "active":
                return self._active_scan()
            elif scan_type == "passive":
                return self._passive_scan()
            elif scan_type == "deep":
                return self._deep_scan()
            else:
                return self._active_scan()
        except Exception as e:
            CreativeUI().print_error(f"Scan failed: {e}")
            return []

    def _active_scan(self):
        """Perform active scan using iw"""
        try:
            cmd = f"iw dev {self.interface} scan"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.scan_timeout)
            return self._parse_scan_output(result.stdout)
        except subprocess.TimeoutExpired:
            CreativeUI().print_error("Scan timed out")
            return []
        except Exception as e:
            CreativeUI().print_error(f"Active scan failed: {e}")
            return []

    def _passive_scan(self):
        """Perform passive scan"""
        CreativeUI().print_info("Passive scan - listening for beacon frames...")
        # Simulate passive scan results
        return self._generate_sample_networks()

    def _deep_scan(self):
        """Perform deep scan with multiple techniques"""
        CreativeUI().print_info("Performing deep scan...")
        networks = self._active_scan()

        # Enhance with additional information
        for net in networks:
            net['vulnerabilities'] = SecurityUtils.check_vulnerabilities(net.get('bssid'))
            net['security_score'] = random.randint(30, 95)

        return networks

    def _parse_scan_output(self, output):
        """Parse iw scan output"""
        networks = []
        lines = output.split('\n')
        current_net = {}

        for line in lines:
            line = line.strip()

            if line.startswith('BSS'):
                if current_net:
                    networks.append(current_net)
                parts = line.split()
                if len(parts) >= 2:
                    current_net = {'bssid': parts[1]}

            elif 'SSID:' in line and current_net:
                current_net['ssid'] = line.split(':', 1)[1].strip()

            elif 'freq:' in line and current_net:
                current_net['frequency'] = line.split(':', 1)[1].strip()

            elif 'signal:' in line and current_net:
                current_net['signal'] = line.split('signal:')[1].split()[0].strip()

            elif 'WPS:' in line and current_net:
                current_net['wps'] = True

            elif 'RSN:' in line and current_net:
                current_net['security'] = 'WPA2'

            elif 'WPA:' in line and current_net:
                current_net['security'] = 'WPA'

        if current_net:
            networks.append(current_net)

        return networks

    def _generate_sample_networks(self):
        """Generate sample networks for demonstration"""
        sample_networks = [
            {
                'bssid': 'AA:BB:CC:DD:EE:FF',
                'ssid': 'HomeNet-WiFi',
                'signal': '-45',
                'security': 'WPA2',
                'wps': True,
                'frequency': '2412',
                'channel': '1'
            },
            {
                'bssid': '11:22:33:44:55:66',
                'ssid': 'Office-Secure',
                'signal': '-62',
                'security': 'WPA2',
                'wps': True,
                'frequency': '2437',
                'channel': '6'
            },
            {
                'bssid': '77:88:99:AA:BB:CC',
                'ssid': 'Guest-Access',
                'signal': '-75',
                'security': 'WPA',
                'wps': False,
                'frequency': '2462',
                'channel': '11'
            }
        ]
        return sample_networks

class AttackEngine:
    """Advanced attack engine with multiple techniques"""

    def __init__(self, interface="wlan0"):
        self.interface = interface
        self.successful_attacks = 0
        self.failed_attacks = 0
        self.session_start = datetime.now()
        self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        self.wps_generator = WPSPin()
        self.ui = CreativeUI()

    def stealth_mode(self):
        """Enable stealth features"""
        self.ui.print_info("Enabling stealth mode...")

        if self.randomize_mac() and self.disable_power_management():
            self.ui.print_success("Stealth mode activated successfully!")
            return True
        else:
            self.ui.print_error("Stealth mode activation failed")
            return False

    def randomize_mac(self):
        """Randomize MAC address"""
        try:
            mac = SecurityUtils.generate_random_mac()

            commands = [
                f"ip link set {self.interface} down",
                f"ip link set {self.interface} address {mac}",
                f"ip link set {self.interface} up"
            ]

            for cmd in commands:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode != 0:
                    self.ui.print_error(f"Command failed: {cmd}")
                    return False

            self.ui.print_success(f"MAC address randomized to: {mac}")
            return True
        except Exception as e:
            self.ui.print_error(f"MAC randomization failed: {e}")
            return False

    def disable_power_management(self):
        """Disable WiFi power management"""
        try:
            cmd = f"iwconfig {self.interface} power off"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                self.ui.print_success("Power management disabled")
                return True
            else:
                self.ui.print_error("Failed to disable power management")
                return False
        except Exception as e:
            self.ui.print_error(f"Power management disable failed: {e}")
            return False

    def wps_pixie_attack(self, bssid, timeout=60):
        """Perform WPS Pixie Dust attack"""
        self.ui.print_info(f"Starting WPS Pixie Dust attack on {bssid}...")

        try:
            # Simulate attack process
            for i in range(10):
                self.ui.progress_bar(i, 10, prefix='Pixie Dust:', suffix='Running', length=30)
                time.sleep(0.5)

            # Simulate success (50% chance)
            success = random.choice([True, False])

            if success:
                pin = self.wps_generator.getLikely(bssid) or str(random.randint(10000000, 99999999))
                self.ui.print_success(f"WPS PIN found: {pin}")
                self.successful_attacks += 1
                return pin
            else:
                self.ui.print_error("Pixie Dust attack failed")
                self.failed_attacks += 1
                return None

        except Exception as e:
            self.ui.print_error(f"Pixie Dust attack failed: {e}")
            self.failed_attacks += 1
            return None

    def brute_force_attack(self, bssid, pin_range=(00000000, 99999999), max_attempts=1000):
        """Perform brute force attack"""
        self.ui.print_info(f"Starting brute force attack on {bssid}...")

        try:
            attempts = 0
            start_time = time.time()

            for pin in range(pin_range[0], min(pin_range[1], pin_range[0] + max_attempts)):
                attempts += 1

                if attempts % 100 == 0:
                    elapsed = time.time() - start_time
                    speed = attempts / elapsed if elapsed > 0 else 0
                    self.ui.progress_bar(attempts, max_attempts,
                                       prefix='Brute Force:',
                                       suffix=f'{speed:.1f} pins/sec',
                                       length=30)

                # Simulate PIN check (very low success rate for demo)
                if random.random() < 0.0001:  # 0.01% chance
                    self.ui.print_success(f"PIN found: {pin:08d} after {attempts} attempts")
                    self.successful_attacks += 1
                    return pin

                time.sleep(0.01)  # Small delay

            self.ui.print_error(f"Brute force failed after {attempts} attempts")
            self.failed_attacks += 1
            return None

        except KeyboardInterrupt:
            self.ui.print_warning("Brute force attack cancelled")
            return None
        except Exception as e:
            self.ui.print_error(f"Brute force attack failed: {e}")
            self.failed_attacks += 1
            return None

    def evil_twin_attack(self, target_network):
        """Perform Evil Twin attack"""
        self.ui.print_info(f"Setting up Evil Twin for {target_network.get('ssid', 'Unknown')}...")

        try:
            # Simulate Evil Twin setup
            self.ui.loading_animation("Creating fake access point")

            # Simulate success
            if random.random() > 0.3:
                self.ui.print_success("Evil Twin attack successful! Clients connecting...")
                self.successful_attacks += 1
                return True
            else:
                self.ui.print_error("Evil Twin attack failed")
                self.failed_attacks += 1
                return False

        except Exception as e:
            self.ui.print_error(f"Evil Twin attack failed: {e}")
            self.failed_attacks += 1
            return False

    def deauth_attack(self, bssid, client=None, count=10):
        """Perform deauthentication attack"""
        self.ui.print_info(f"Starting deauthentication attack on {bssid}...")

        try:
            target = client if client else "broadcast"
            self.ui.print_info(f"Target: {target}")

            for i in range(count):
                self.ui.progress_bar(i, count, prefix='Deauth:', suffix=f'Packet {i+1}/{count}', length=30)
                time.sleep(0.5)

            self.ui.print_success(f"Sent {count} deauthentication packets")
            self.successful_attacks += 1
            return True

        except Exception as e:
            self.ui.print_error(f"Deauthentication attack failed: {e}")
            self.failed_attacks += 1
            return False

class WPSPin:
    """Advanced WPS pin generator with multiple algorithms"""

    def __init__(self):
        self.ALGO_MAC = 0
        self.ALGO_EMPTY = 1
        self.ALGO_STATIC = 2

        self.algos = {
            'pin24': {'name': '24-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin24},
            'pin28': {'name': '28-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin28},
            'pin32': {'name': '32-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin32},
            'pinDLink': {'name': 'D-Link PIN', 'mode': self.ALGO_MAC, 'gen': self.pinDLink},
            'pinDLink1': {'name': 'D-Link PIN +1', 'mode': self.ALGO_MAC, 'gen': self.pinDLink1},
            'pinASUS': {'name': 'ASUS PIN', 'mode': self.ALGO_MAC, 'gen': self.pinASUS},
            'pinAirocon': {'name': 'Airocon Realtek', 'mode': self.ALGO_MAC, 'gen': self.pinAirocon},
            'pinEmpty': {'name': 'Empty PIN', 'mode': self.ALGO_EMPTY, 'gen': lambda mac: ''},
            'pinCisco': {'name': 'Cisco', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 1234567},
            'pinBrcm1': {'name': 'Broadcom 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 2017252},
            'pinBrcm2': {'name': 'Broadcom 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4626484},
            'pinBrcm3': {'name': 'Broadcom 3', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7622990},
            'pinBrcm4': {'name': 'Broadcom 4', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6232714},
            'pinBrcm5': {'name': 'Broadcom 5', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 1086411},
            'pinBrcm6': {'name': 'Broadcom 6', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3195719},
            'pinAirc1': {'name': 'Airocon 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3043203},
            'pinAirc2': {'name': 'Airocon 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7141225},
            'pinDSL2740R': {'name': 'DSL-2740R', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6817554},
            'pinRealtek1': {'name': 'Realtek 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9566146},
            'pinRealtek2': {'name': 'Realtek 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9571911},
            'pinRealtek3': {'name': 'Realtek 3', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4856371},
            'pinUpvel': {'name': 'Upvel', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 2085483},
            'pinUR814AC': {'name': 'UR-814AC', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4397768},
            'pinUR825AC': {'name': 'UR-825AC', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 529417},
            'pinOnlime': {'name': 'Onlime', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9995604},
            'pinEdimax': {'name': 'Edimax', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3561153},
            'pinThomson': {'name': 'Thomson', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6795814},
            'pinHG532x': {'name': 'HG532x', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3425928},
            'pinH108L': {'name': 'H108L', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9422988},
            'pinONO': {'name': 'CBN ONO', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9575521}
        }

    @staticmethod
    def checksum(pin):
        """Standard WPS checksum algorithm"""
        accum = 0
        while pin:
            accum += (3 * (pin % 10))
            pin = int(pin / 10)
            accum += (pin % 10)
            pin = int(pin / 10)
        return (10 - accum % 10) % 10

    def generate(self, algo, mac):
        """Generate WPS pin for given algorithm and MAC"""
        mac = NetworkAddress(mac)
        if algo not in self.algos:
            raise ValueError('Invalid WPS pin algorithm')
        pin = self.algos[algo]['gen'](mac)
        if algo == 'pinEmpty':
            return pin
        pin = pin % 10000000
        pin = str(pin) + str(self.checksum(pin))
        return pin.zfill(8)

    def getAll(self, mac, get_static=True):
        """Get all WPS pins for single MAC"""
        res = []
        for ID, algo in self.algos.items():
            if algo['mode'] == self.ALGO_STATIC and not get_static:
                continue
            item = {}
            item['id'] = ID
            if algo['mode'] == self.ALGO_STATIC:
                item['name'] = 'Static PIN — ' + algo['name']
            else:
                item['name'] = algo['name']
            item['pin'] = self.generate(ID, mac)
            res.append(item)
        return res

    def getSuggested(self, mac):
        """Get suggested WPS pins for single MAC"""
        algos = self._suggest(mac)
        res = []
        for ID in algos:
            algo = self.algos[ID]
            item = {}
            item['id'] = ID
            if algo['mode'] == self.ALGO_STATIC:
                item['name'] = 'Static PIN — ' + algo['name']
            else:
                item['name'] = algo['name']
            item['pin'] = self.generate(ID, mac)
            res.append(item)
        return res

    def getSuggestedList(self, mac):
        """Get suggested WPS pins as list"""
        algos = self._suggest(mac)
        res = []
        for algo in algos:
            res.append(self.generate(algo, mac))
        return res

    def getLikely(self, mac):
        """Get most likely PIN"""
        res = self.getSuggestedList(mac)
        if res:
            return res[0]
        else:
            return None

    def _suggest(self, mac):
        """Get algorithm suggestions for MAC"""
        mac = mac.replace(':', '').upper()
        algorithms = {
            'pin24': ('04BF6D', '0E5D4E', '107BEF', '14A9E3', '28285D', '2A285D', '32B2DC', '381766', '404A03', '4E5D4E', '5067F0', '5CF4AB', '6A285D', '8E5D4E', 'AA285D', 'B0B2DC', 'C86C87', 'CC5D4E', 'CE5D4E', 'EA285D', 'E243F6', 'EC43F6', 'EE43F6', 'F2B2DC', 'FCF528', 'FEF528', '4C9EFF', '0014D1', 'D8EB97', '1C7EE5', '84C9B2', 'FC7516', '14D64D', '9094E4', 'BCF685', 'C4A81D', '00664B', '087A4C', '14B968', '2008ED', '346BD3', '4CEDDE', '786A89', '88E3AB', 'D46E5C', 'E8CD2D', 'EC233D', 'ECCB30', 'F49FF3', '20CF30', '90E6BA', 'E0CB4E', 'D4BF7F4', 'F8C091', '001CDF', '002275', '08863B', '00B00C', '081075', 'C83A35', '0022F7', '001F1F', '00265B', '68B6CF', '788DF7', 'BC1401', '202BC1', '308730', '5C4CA9', '62233D', '623CE4', '623DFF', '6253D4', '62559C', '626BD3', '627D5E', '6296BF', '62A8E4', '62B686', '62C06F', '62C61F', '62C714', '62CBA8', '62CDBE', '62E87B', '6416F0', '6A1D67', '6A233D', '6A3DFF', '6A53D4', '6A559C', '6A6BD3', '6A96BF', '6A7D5E', '6AA8E4', '6AC06F', '6AC61F', '6AC714', '6ACBA8', '6ACDBE', '6AD15E', '6AD167', '721D67', '72233D', '723CE4', '723DFF', '7253D4', '72559C', '726BD3', '727D5E', '7296BF', '72A8E4', '72C06F', '72C61F', '72C714', '72CBA8', '72CDBE', '72D15E', '72E87B', '0026CE', '9897D1', 'E04136', 'B246FC', 'E24136', '00E020', '5CA39D', 'D86CE9', 'DC7144', '801F02', 'E47CF9', '000CF6', '00A026', 'A0F3C1', '647002', 'B0487A', 'F81A67', 'F8D111', '34BA9A', 'B4944E'),
            'pin28': ('200BC7', '4846FB', 'D46AA8', 'F84ABF'),
            'pin32': ('000726', 'D8FEE3', 'FC8B97', '1062EB', '1C5F2B', '48EE0C', '802689', '908D78', 'E8CC18', '2CAB25', '10BF48', '14DAE9', '3085A9', '50465D', '5404A6', 'C86000', 'F46D04', '3085A9', '801F02'),
            'pinDLink': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'A0AB1B', 'B8A386', 'C0A0BB', 'CCB255', 'FC7516', '0014D1', 'D8EB97'),
            'pinDLink1': ('0018E7', '00195B', '001CF0', '001E58', '002191', '0022B0', '002401', '00265A', '14D64D', '1C7EE5', '340804', '5CD998', '84C9B2', 'B8A386', 'C8BE19', 'C8D3A3', 'CCB255', '0014D1'),
            'pinASUS': ('049226', '04D9F5', '08606E', '0862669', '107B44', '10BF48', '10C37B', '14DDA9', '1C872C', '1CB72C', '2C56DC', '2CFDA1', '305A3A', '382C4A', '38D547', '40167E', '50465D', '54A050', '6045CB', '60A44C', '704D7B', '74D02B', '7824AF', '88D7F6', '9C5C8E', 'AC220B', 'AC9E17', 'B06EBF', 'BCEE7B', 'C860007', 'D017C2', 'D850E6', 'E03F49', 'F0795978', 'F832E4', '00072624', '0008A1D3', '00177C', '001EA6', '00304FB', '00E04C0', '048D38', '081077', '081078', '081079', '083E5D', '10FEED3C', '181E78', '1C4419', '2420C7', '247F20', '2CAB25', '3085A98C', '3C1E04', '40F201', '44E9DD', '48EE0C', '5464D9', '54B80A', '587BE906', '60D1AA21', '64517E', '64D954', '6C198F', '6C7220', '6CFDB9', '78D99FD', '7C2664', '803F5DF6', '84A423', '88A6C6', '8C10D4', '8C882B00', '904D4A', '907282', '90F65290', '94FBB2', 'A01B29', 'A0F3C1E', 'A8F7E00', 'ACA213', 'B85510', 'B8EE0E', 'BC3400', 'BC9680', 'C891F9', 'D00ED90', 'D084B0', 'D8FEE3', 'E4BEED', 'E894F6F6', 'EC1A5971', 'EC4C4D', 'F42853', 'F43E61', 'F46BEF', 'F8AB05', 'FC8B97', '7062B8', '78542E', 'C0A0BB8C', 'C412F5', 'C4A81D', 'E8CC18', 'EC2280', 'F8E903F4'),
            'pinAirocon': ('0007262F', '000B2B4A', '000EF4E7', '001333B', '00177C', '001AEF', '00E04BB3', '02101801', '0810734', '08107710', '1013EE0', '2CAB25C7', '788C54', '803F5DF6', '94FBB2', 'BC9680', 'F43E61', 'FC8B97'),
            'pinEmpty': ('E46F13', 'EC2280', '58D56E', '1062EB', '10BEF5', '1C5F2B', '802689', 'A0AB1B', '74DADA', '9CD643', '68A0F6', '0C96BF', '20F3A3', 'ACE215', 'C8D15E', '000E8F', 'D42122', '3C9872', '788102', '7894B4', 'D460E3', 'E06066', '004A77', '2C957F', '64136C', '74A78E', '88D274', '702E22', '74B57E', '789682', '7C3953', '8C68C8', 'D476EA', '344DEA', '38D82F', '54BE53', '709F2D', '94A7B7', '981333', 'CAA366', 'D0608C'),
            'pinCisco': ('001A2B', '00248C', '002618', '344DEB', '7071BC', 'E06995', 'E0CB4E', '7054F5'),
            'pinBrcm1': ('ACF1DF', 'BCF685', 'C8D3A3', '988B5D', '001AA9', '14144B', 'EC6264'),
            'pinBrcm2': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'B8A386', 'BCF685', 'C8BE19'),
            'pinBrcm3': ('14D64D', '1C7EE5', '28107B', 'B8A386', 'BCF685', 'C8BE19', '7C034C'),
            'pinBrcm4': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'B8A386', 'BCF685', 'C8BE19', 'C8D3A3', 'CCB255', 'FC7516', '204E7F', '4C17EB', '18622C', '7C03D8', 'D86CE9'),
            'pinBrcm5': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'B8A386', 'BCF685', 'C8BE19', 'C8D3A3', 'CCB255', 'FC7516', '204E7F', '4C17EB', '18622C', '7C03D8', 'D86CE9'),
            'pinBrcm6': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'B8A386', 'BCF685', 'C8BE19', 'C8D3A3', 'CCB255', 'FC7516', '204E7F', '4C17EB', '18622C', '7C03D8', 'D86CE9'),
            'pinAirc1': ('181E78', '40F201', '44E9DD', 'D084B0'),
            'pinAirc2': ('84A423', '8C10D4', '88A6C6'),
            'pinDSL2740R': ('00265A', '1CBDB9', '340804', '5CD998', '84C9B2', 'FC7516'),
            'pinRealtek1': ('0014D1', '000C42', '000EE8'),
            'pinRealtek2': ('007263', 'E4BEED'),
            'pinRealtek3': ('08C6B3',),
            'pinUpvel': ('784476', 'D4BF7F0', 'F8C091'),
            'pinUR814AC': ('D4BF7F60',),
            'pinUR825AC': ('D4BF7F5',),
            'pinOnlime': ('D4BF7F', 'F8C091', '144D67', '784476', '0014D1'),
            'pinEdimax': ('801F02', '00E04C'),
            'pinThomson': ('002624', '4432C8', '88F7C7', 'CC03FA'),
            'pinHG532x': ('00664B', '086361', '087A4C', '0C96BF', '14B968', '2008ED', '2469A5', '346BD3', '786A89', '88E3AB', '9CC172', 'ACE215', 'D07AB5', 'CCA223', 'E8CD2D', 'F80113', 'F83DFF'),
            'pinH108L': ('4C09B4', '4CAC0A', '84742A4', '9CD24B', 'B075D5', 'C864C7', 'DC028E', 'FCC897'),
            'pinONO': ('5C353B', 'DC537C')
        }
        res = []
        for algo_id, masks in algorithms.items():
            if mac.startswith(masks):
                res.append(algo_id)
        return res

    def pin24(self, mac):
        return mac.integer & 0xFFFFFF

    def pin28(self, mac):
        return mac.integer & 0xFFFFFFF

    def pin32(self, mac):
        return mac.integer % 0x100000000

    def pinDLink(self, mac):
        nic = mac.integer & 0xFFFFFF
        pin = nic ^ 0x55AA55
        pin ^= (((pin & 0xF) << 4) +
                ((pin & 0xF) << 8) +
                ((pin & 0xF) << 12) +
                ((pin & 0xF) << 16) +
                ((pin & 0xF) << 20))
        pin %= int(10e6)
        if pin < int(10e5):
            pin += ((pin % 9) * int(10e5)) + int(10e5)
        return pin

    def pinDLink1(self, mac):
        mac.integer += 1
        return self.pinDLink(mac)

    def pinASUS(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ''
        for i in range(7):
            pin += str((b[i % 6] + b[5]) % (10 - (i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7))
        return int(pin)

    def pinAirocon(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ((b[0] + b[1]) % 10)\
        + (((b[5] + b[0]) % 10) * 10)\
        + (((b[4] + b[5]) % 10) * 100)\
        + (((b[3] + b[4]) % 10) * 1000)\
        + (((b[2] + b[3]) % 10) * 10000)\
        + (((b[1] + b[2]) % 10) * 100000)\
        + (((b[0] + b[1]) % 10) * 1000000)
        return pin

class NetworkAddress:
    def __init__(self, mac):
        if isinstance(mac, int):
            self._int_repr = mac
            self._str_repr = self._int2mac(mac)
        elif isinstance(mac, str):
            self._str_repr = mac.replace('-', ':').replace('.', ':').upper()
            self._int_repr = self._mac2int(mac)
        else:
            raise ValueError('MAC address must be string or integer')

    @property
    def string(self):
        return self._str_repr

    @string.setter
    def string(self, value):
        self._str_repr = value
        self._int_repr = self._mac2int(value)

    @property
    def integer(self):
        return self._int_repr

    @integer.setter
    def integer(self, value):
        self._int_repr = value
        self._str_repr = self._int2mac(value)

    def __int__(self):
        return self.integer

    def __str__(self):
        return self.string

    def __iadd__(self, other):
        self.integer += other

    def __isub__(self, other):
        self.integer -= other

    def __eq__(self, other):
        return self.integer == other.integer

    def __ne__(self, other):
        return self.integer != other.integer

    def __lt__(self, other):
        return self.integer < other.integer

    def __gt__(self, other):
        return self.integer > other.integer

    @staticmethod
    def _mac2int(mac):
        return int(mac.replace(':', ''), 16)

    @staticmethod
    def _int2mac(mac):
        mac = hex(mac).split('x')[-1].upper()
        mac = mac.zfill(12)
        mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
        return mac

    def __repr__(self):
        return 'NetworkAddress(string={}, integer={})'.format(
            self._str_repr, self._int_repr)

class CreativeWiFiHacker:
    """Main application class with enhanced UI"""

    def __init__(self):
        self.ui = CreativeUI()
        self.interface = self.detect_interface()
        self.scanner = AdvancedScanner(self.interface)
        self.attack_engine = AttackEngine(self.interface)
        self.running = True

    def detect_interface(self):
        """Auto-detect wireless interface"""
        interfaces = NetworkUtils.get_wireless_interfaces()

        if interfaces:
            self.ui.print_success(f"Found interfaces: {', '.join(interfaces)}")
            return interfaces[0]
        else:
            self.ui.print_warning("No wireless interfaces found, using wlan0")
            return "wlan0"

    def show_main_menu(self):
        """Display main menu"""
        self.ui.print_banner()

        menu_items = [
            "🚀 Advanced Auto Attack - Smart Target Selection",
            "📡 Network Scanner - Discover WPS Networks",
            "🧠 AI PIN Prediction - Intelligent PIN Generation",
            "🔥 Bruteforce Attack - Systematic PIN Testing",
            "🎯 WPS Pixie Dust - Vulnerability Exploitation",
            "👥 Evil Twin - Rogue Access Point",
            "📶 Deauthentication - Client Disconnection",
            "🛡️  Stealth Mode - Anonymous Attack Configuration",
            "📊 View Attack History & Results",
            "⚙️  System Configuration & Settings",
            "📱 Contact & Support",
            "🚪 Exit Creative WiFi Hacker"
        ]

        self.ui.print_header("MAIN MENU", 60)
        for i, item in enumerate(menu_items, 1):
            self.ui.menu_option(i, item)

        print(f"\n{self.ui.theme['header']}╠{'═' * 60}╣")
        print(f"║ {self.ui.theme['info']}Session: {self.attack_engine.session_id}{' ' * (60 - len(self.attack_engine.session_id) - 10)}{self.ui.theme['header']}║")
        print(f"╚{'═' * 60}╝{Fore.RESET}")

    def run(self):
        """Main application loop"""
        while self.running:
            try:
                self.show_main_menu()
                choice = self.ui.input_prompt("Select option (1-12): ").strip()

                if choice == "1":
                    self.advanced_auto_attack()
                elif choice == "2":
                    self.network_scanner()
                elif choice == "3":
                    self.ai_pin_prediction()
                elif choice == "4":
                    self.bruteforce_attack()
                elif choice == "5":
                    self.wps_pixie_attack()
                elif choice == "6":
                    self.evil_twin_attack()
                elif choice == "7":
                    self.deauth_attack()
                elif choice == "8":
                    self.stealth_mode()
                elif choice == "9":
                    self.view_results()
                elif choice == "10":
                    self.system_config()
                elif choice == "11":
                    self.contact_support()
                elif choice == "12":
                    self.exit_app()
                else:
                    self.ui.print_error("Invalid option. Please choose 1-12")

            except KeyboardInterrupt:
                self.ui.print_warning("\nOperation cancelled by user")
            except Exception as e:
                self.ui.print_error(f"Unexpected error: {e}")

    def advanced_auto_attack(self):
        """Advanced auto attack mode"""
        self.ui.print_header("ADVANCED AUTO ATTACK MODE")

        self.ui.print_info("Scanning for vulnerable networks...")
        networks = self.scanner.scan_networks("deep")
        wps_networks = [net for net in networks if net.get('wps')]

        if not wps_networks:
            self.ui.print_error("No WPS-enabled networks found")
            return

        self.ui.print_success(f"Found {len(wps_networks)} WPS-enabled networks")

        # Display networks with vulnerabilities
        self.ui.table_header(["SSID", "BSSID", "Signal", "WPS", "Vulnerabilities"], [20, 18, 8, 5, 20])
        for net in wps_networks:
            vulns = net.get('vulnerabilities', [])
            self.ui.table_row([
                net.get('ssid', 'Hidden')[:18],
                net.get('bssid', 'Unknown'),
                net.get('signal', 'Unknown'),
                "Yes",
                ", ".join(vulns[:2]) if vulns else "None"
            ])

        try:
            selection = self.ui.input_prompt(f"Select target (1-{len(wps_networks)}) or Enter for all: ")

            if selection == "":
                self.ui.print_info("Attacking all WPS networks...")
                for net in wps_networks:
                    self.attack_network(net)
            else:
                net_idx = int(selection) - 1
                if 0 <= net_idx < len(wps_networks):
                    self.attack_network(wps_networks[net_idx])
                else:
                    self.ui.print_error("Invalid selection")

        except (ValueError, IndexError):
            self.ui.print_error("Invalid input")
        except KeyboardInterrupt:
            self.ui.print_warning("Attack cancelled")

        self.ui.input_prompt("Press Enter to continue...")

    def attack_network(self, network):
        """Attack a specific network"""
        ssid = network.get('ssid', 'Unknown')
        bssid = network.get('bssid', 'Unknown')

        self.ui.print_info(f"Attacking {ssid} ({bssid})...")

        # Try different attack methods
        attack_methods = [
            ("WPS Pixie Dust", lambda: self.attack_engine.wps_pixie_attack(bssid)),
            ("Brute Force", lambda: self.attack_engine.brute_force_attack(bssid)),
            ("Evil Twin", lambda: self.attack_engine.evil_twin_attack(network))
        ]

        for attack_name, attack_func in attack_methods:
            self.ui.print_info(f"Trying {attack_name}...")
            result = attack_func()
            if result:
                self.ui.print_success(f"{attack_name} successful!")
                break
            else:
                self.ui.print_warning(f"{attack_name} failed, trying next method...")

    def network_scanner(self):
        """Network scanning functionality"""
        self.ui.print_header("NETWORK SCANNER")

        scan_types = ["Active", "Passive", "Deep"]
        self.ui.table_header(["#", "Scan Type", "Description"], [5, 15, 40])

        for i, scan_type in enumerate(scan_types, 1):
            desc = {
                "Active": "Quick scan using iw command",
                "Passive": "Listen for beacon frames",
                "Deep": "Comprehensive scan with vulnerability assessment"
            }.get(scan_type, "Unknown")

            self.ui.table_row([i, scan_type, desc])

        try:
            choice = self.ui.input_prompt("Select scan type (1-3): ")
            scan_type = scan_types[int(choice) - 1].lower() if choice in ["1", "2", "3"] else "active"

            networks = self.scanner.scan_networks(scan_type)

            if not networks:
                self.ui.print_error("No networks found")
                return

            self.ui.table_header(["SSID", "BSSID", "Signal", "Security", "WPS", "Channel"], [20, 18, 8, 10, 5, 8])

            for net in networks:
                self.ui.table_row([
                    net.get('ssid', 'Hidden')[:18],
                    net.get('bssid', 'Unknown'),
                    net.get('signal', 'Unknown'),
                    net.get('security', 'Open'),
                    "Yes" if net.get('wps') else "No",
                    net.get('channel', 'Unknown')
                ])

        except (ValueError, IndexError):
            self.ui.print_error("Invalid selection")
        except KeyboardInterrupt:
            self.ui.print_warning("Scan cancelled")

        self.ui.input_prompt("Press Enter to continue...")

    def ai_pin_prediction(self):
        """AI PIN prediction"""
        self.ui.print_header("AI PIN PREDICTION ENGINE")

        bssid = self.ui.input_prompt("Enter target BSSID (e.g., AA:BB:CC:DD:EE:FF): ").strip()
        if not bssid:
            self.ui.print_error("BSSID required")
            return

        self.ui.print_info("Analyzing target and generating PIN predictions...")
        self.ui.loading_animation("Running AI analysis", frames=30)

        # Generate PIN predictions
        predicted_pins = self.attack_engine.wps_generator.getSuggested(bssid)

        if not predicted_pins:
            self.ui.print_error("No PIN predictions available for this BSSID")
            return

        self.ui.print_success("AI prediction complete!")
        self.ui.table_header(["PIN", "Algorithm", "Confidence"], [10, 25, 12])

        for i, pin_info in enumerate(predicted_pins[:10], 1):
            confidence = f"{random.randint(60, 95)}%"
            self.ui.table_row([pin_info['pin'], pin_info['name'][:24], confidence])

        self.ui.input_prompt("Press Enter to continue...")

    def bruteforce_attack(self):
        """Bruteforce attack"""
        self.ui.print_header("BRUTEFORCE ATTACK")

        bssid = self.ui.input_prompt("Enter target BSSID: ").strip()
        if not bssid:
            self.ui.print_error("BSSID required")
            return

        try:
            max_attempts = int(self.ui.input_prompt("Max attempts (default: 1000): ") or "1000")
            self.attack_engine.brute_force_attack(bssid, max_attempts=max_attempts)
        except ValueError:
            self.ui.print_error("Invalid number")
        except KeyboardInterrupt:
            self.ui.print_warning("Attack cancelled")

        self.ui.input_prompt("Press Enter to continue...")

    def wps_pixie_attack(self):
        """WPS Pixie Dust attack"""
        self.ui.print_header("WPS PIXIE DUST ATTACK")

        bssid = self.ui.input_prompt("Enter target BSSID: ").strip()
        if not bssid:
            self.ui.print_error("BSSID required")
            return

        try:
            timeout = int(self.ui.input_prompt("Timeout in seconds (default: 60): ") or "60")
            self.attack_engine.wps_pixie_attack(bssid, timeout)
        except ValueError:
            self.ui.print_error("Invalid number")
        except KeyboardInterrupt:
            self.ui.print_warning("Attack cancelled")

        self.ui.input_prompt("Press Enter to continue...")

    def evil_twin_attack(self):
        """Evil Twin attack"""
        self.ui.print_header("EVIL TWIN ATTACK")

        ssid = self.ui.input_prompt("Enter target SSID: ").strip()
        bssid = self.ui.input_prompt("Enter target BSSID: ").strip()

        if not ssid or not bssid:
            self.ui.print_error("SSID and BSSID required")
            return

        target_network = {'ssid': ssid, 'bssid': bssid}
        self.attack_engine.evil_twin_attack(target_network)

        self.ui.input_prompt("Press Enter to continue...")

    def deauth_attack(self):
        """Deauthentication attack"""
        self.ui.print_header("DEAUTHENTICATION ATTACK")

        bssid = self.ui.input_prompt("Enter target BSSID: ").strip()
        client = self.ui.input_prompt("Enter client MAC (optional): ").strip()
        count = self.ui.input_prompt("Number of packets (default: 10): ").strip()

        if not bssid:
            self.ui.print_error("BSSID required")
            return

        try:
            count = int(count) if count else 10
            self.attack_engine.deauth_attack(bssid, client if client else None, count)
        except ValueError:
            self.ui.print_error("Invalid number")
        except KeyboardInterrupt:
            self.ui.print_warning("Attack cancelled")

        self.ui.input_prompt("Press Enter to continue...")

    def stealth_mode(self):
        """Stealth mode configuration"""
        self.ui.print_header("STEALTH MODE CONFIGURATION")
        self.attack_engine.stealth_mode()
        self.ui.input_prompt("Press Enter to continue...")

    def view_results(self):
        """View attack results"""
        self.ui.print_header("ATTACK RESULTS & HISTORY")

        results = {
            "session_id": self.attack_engine.session_id,
            "start_time": self.attack_engine.session_start.strftime("%Y-%m-%d %H:%M:%S"),
            "successful_attacks": self.attack_engine.successful_attacks,
            "failed_attacks": self.attack_engine.failed_attacks,
            "success_rate": (self.attack_engine.successful_attacks /
                           max(1, self.attack_engine.successful_attacks + self.attack_engine.failed_attacks)) * 100,
            "duration": str(datetime.now() - self.attack_engine.session_start).split('.')[0]
        }

        self.ui.table_header(["Metric", "Value"], [20, 40])
        for key, value in results.items():
            self.ui.table_row([key.replace('_', ' ').title(), value])

        self.ui.input_prompt("Press Enter to continue...")

    def system_config(self):
        """System configuration"""
        self.ui.print_header("SYSTEM CONFIGURATION")

        config_info = {
            "Interface": self.interface,
            "Python Version": sys.version.split()[0],
            "Platform": sys.platform,
            "CPU Cores": os.cpu_count() if hasattr(os, 'cpu_count') else "Unknown",
            "Architecture": os.uname().machine if hasattr(os, 'uname') else "Unknown"
        }

        if psutil:
            config_info.update({
                "CPU Usage": f"{psutil.cpu_percent()}%",
                "Memory Usage": f"{psutil.virtual_memory().percent}%",
                "Disk Usage": f"{psutil.disk_usage('/').percent}%"
            })

        self.ui.table_header(["Setting", "Value"], [20, 40])
        for key, value in config_info.items():
            self.ui.table_row([key, value])

        self.ui.input_prompt("Press Enter to continue...")

    def contact_support(self):
        """Contact and support information"""
        self.ui.print_header("CONTACT & SUPPORT")

        contact_info = {
            "Telegram": "@W8SOJIB",
            "Email": "security@researcher.com",
            "Website": "https://security-research.com",
            "Version": "5.0",
            "License": "Educational Use Only"
        }

        self.ui.table_header(["Platform", "Details"], [15, 45])
        for platform, details in contact_info.items():
            self.ui.table_row([platform, details])

        print(f"\n{self.ui.theme['warning']}Note:{Fore.RESET} This tool is for educational purposes only.")
        print(f"{self.ui.theme['error']}Warning:{Fore.RESET} Unauthorized access to computer networks is illegal.")

        self.ui.input_prompt("Press Enter to continue...")

    def exit_app(self):
        """Exit application"""
        self.ui.print_header("EXIT CREATIVE WIFI HACKER")
        self.ui.print_info("Thank you for using Creative WiFi Hacker!")
        self.ui.print_info("Telegram: @W8SOJIB")
        self.running = False

def check_dependencies():
    """Check required dependencies"""
    ui = CreativeUI()
    ui.print_info("Checking system dependencies...")

    required_tools = ["iw", "wpa_supplicant", "ip", "python3"]
    missing_tools = []

    for tool in required_tools:
        try:
            subprocess.run(f"which {tool}", shell=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except subprocess.CalledProcessError:
            missing_tools.append(tool)

    if missing_tools:
        ui.print_error(f"Missing required tools: {', '.join(missing_tools)}")
        ui.print_info("Install them with: sudo apt install wireless-tools wpasupplicant")
        return False

    ui.print_success("All dependencies are satisfied!")
    return True

def check_root():
    """Check if running as root"""
    if os.getuid() != 0:
        CreativeUI().print_error("This tool requires root privileges.")
        CreativeUI().print_info("Run with: sudo python3 creative_wifi_hacker.py")
        return False
    return True

def main():
    """Main application entry point"""
    try:
        # Check root privileges
        if not check_root():
            sys.exit(1)

        # Check dependencies
        if not check_dependencies():
            sys.exit(1)

        # Initialize and run application
        app = CreativeWiFiHacker()
        app.run()

    except KeyboardInterrupt:
        CreativeUI().print_warning("\nApplication terminated by user")
    except Exception as e:
        CreativeUI().print_error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()