"""
Network detection utilities for smart attendance system.
Provides functions to auto-detect IP configuration, subnets, and network interfaces.
"""

import subprocess
import socket
import ipaddress
import psutil
import re
import json
from typing import List, Dict, Tuple, Optional
from datetime import datetime
from django.conf import settings
from django.utils import timezone
from .models import CampusSubnet


class NetworkDetector:
    """Network detection and configuration utility class"""
    
    def __init__(self):
        self.detected_interfaces = []
        self.detected_subnets = []
        self.system_info = {}
    
    def get_system_network_info(self) -> Dict:
        """Get comprehensive system network information"""
        info = {
            'hostname': socket.gethostname(),
            'platform': self._get_platform(),
            'interfaces': [],
            'routes': [],
            'dns_servers': [],
            'detected_at': timezone.now().isoformat()
        }
        
        # Get network interfaces
        info['interfaces'] = self.get_network_interfaces()
        
        # Get routing table
        info['routes'] = self.get_routing_table()
        
        # Get DNS configuration
        info['dns_servers'] = self.get_dns_servers()
        
        self.system_info = info
        return info
    
    def get_network_interfaces(self) -> List[Dict]:
        """Detect all network interfaces and their configurations"""
        interfaces = []
        
        try:
            # Use psutil to get network interface information
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            
            for interface_name, addresses in net_if_addrs.items():
                interface_info = {
                    'name': interface_name,
                    'addresses': [],
                    'is_active': interface_name in net_if_stats and net_if_stats[interface_name].isup,
                    'mtu': net_if_stats[interface_name].mtu if interface_name in net_if_stats else None,
                    'speed': net_if_stats[interface_name].speed if interface_name in net_if_stats else None
                }
                
                for addr in addresses:
                    if addr.family == socket.AF_INET:  # IPv4
                        try:
                            ip = ipaddress.IPv4Address(addr.address)
                            netmask = ipaddress.IPv4Address(addr.netmask) if addr.netmask else None
                            
                            if netmask:
                                # Calculate network and subnet
                                network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                                
                                interface_info['addresses'].append({
                                    'type': 'IPv4',
                                    'address': str(ip),
                                    'netmask': str(netmask),
                                    'network': str(network.network_address),
                                    'subnet': str(network),
                                    'broadcast': str(network.broadcast_address),
                                    'is_private': ip.is_private,
                                    'is_loopback': ip.is_loopback,
                                    'prefix_length': network.prefixlen
                                })
                        except Exception as e:
                            print(f"Error processing IPv4 address {addr.address}: {e}")
                    
                    elif addr.family == socket.AF_INET6:  # IPv6
                        try:
                            ip = ipaddress.IPv6Address(addr.address.split('%')[0])  # Remove zone identifier
                            interface_info['addresses'].append({
                                'type': 'IPv6',
                                'address': str(ip),
                                'is_private': ip.is_private,
                                'is_loopback': ip.is_loopback
                            })
                        except Exception as e:
                            print(f"Error processing IPv6 address {addr.address}: {e}")
                
                if interface_info['addresses']:  # Only add interfaces with valid addresses
                    interfaces.append(interface_info)
        
        except Exception as e:
            print(f"Error getting network interfaces: {e}")
        
        self.detected_interfaces = interfaces
        return interfaces
    
    def get_routing_table(self) -> List[Dict]:
        """Get system routing table information"""
        routes = []
        
        try:
            if self._is_windows():
                routes = self._get_windows_routes()
            else:
                routes = self._get_unix_routes()
        except Exception as e:
            print(f"Error getting routing table: {e}")
        
        return routes
    
    def _get_windows_routes(self) -> List[Dict]:
        """Get Windows routing table using route command"""
        routes = []
        
        try:
            result = subprocess.run(['route', 'print'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                parsing_ipv4 = False
                
                for line in lines:
                    line = line.strip()
                    if 'IPv4 Route Table' in line:
                        parsing_ipv4 = True
                        continue
                    
                    if parsing_ipv4 and line and not line.startswith('='):
                        # Parse route line: Network Destination Netmask Gateway Interface Metric
                        parts = line.split()
                        if len(parts) >= 5 and self._is_valid_ip(parts[0]):
                            routes.append({
                                'destination': parts[0],
                                'netmask': parts[1],
                                'gateway': parts[2],
                                'interface': parts[3],
                                'metric': parts[4] if len(parts) > 4 else None
                            })
                    
                    if 'IPv6 Route Table' in line:
                        parsing_ipv4 = False
        
        except subprocess.TimeoutExpired:
            print("Route command timed out")
        except Exception as e:
            print(f"Error running route command: {e}")
        
        return routes
    
    def _get_unix_routes(self) -> List[Dict]:
        """Get Unix/Linux routing table using ip route or netstat"""
        routes = []
        
        try:
            # Try ip route first (modern Linux)
            try:
                result = subprocess.run(['ip', 'route'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            routes.append({'route_line': line.strip()})
            except FileNotFoundError:
                # Fall back to netstat
                result = subprocess.run(['netstat', '-rn'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n')[2:]:  # Skip headers
                        if line.strip():
                            routes.append({'route_line': line.strip()})
        
        except Exception as e:
            print(f"Error getting Unix routes: {e}")
        
        return routes
    
    def get_dns_servers(self) -> List[str]:
        """Get configured DNS servers"""
        dns_servers = []
        
        try:
            if self._is_windows():
                dns_servers = self._get_windows_dns()
            else:
                dns_servers = self._get_unix_dns()
        except Exception as e:
            print(f"Error getting DNS servers: {e}")
        
        return dns_servers
    
    def _get_windows_dns(self) -> List[str]:
        """Get Windows DNS configuration"""
        dns_servers = []
        
        try:
            result = subprocess.run(['nslookup', 'localhost'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Server:' in line and 'Address:' in line:
                        # Extract IP from "Server: [IP]" format
                        match = re.search(r'\[(.*?)\]', line)
                        if match:
                            dns_servers.append(match.group(1))
        except Exception as e:
            print(f"Error getting Windows DNS: {e}")
        
        return dns_servers
    
    def _get_unix_dns(self) -> List[str]:
        """Get Unix/Linux DNS configuration"""
        dns_servers = []
        
        try:
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.strip().startswith('nameserver'):
                        dns_server = line.strip().split()[1]
                        if self._is_valid_ip(dns_server):
                            dns_servers.append(dns_server)
        except FileNotFoundError:
            print("resolv.conf not found")
        except Exception as e:
            print(f"Error reading resolv.conf: {e}")
        
        return dns_servers
    
    def detect_campus_subnets(self, confidence_threshold: float = 0.7) -> List[Dict]:
        """
        Detect likely campus subnets based on network analysis
        
        Args:
            confidence_threshold: Minimum confidence level for subnet suggestions
            
        Returns:
            List of detected subnets with confidence scores
        """
        suggested_subnets = []
        
        # Get current network interfaces
        interfaces = self.get_network_interfaces()
        
        for interface in interfaces:
            if not interface['is_active']:
                continue
                
            for addr_info in interface['addresses']:
                if addr_info['type'] != 'IPv4' or addr_info['is_loopback']:
                    continue
                
                subnet_info = {
                    'subnet': addr_info['subnet'],
                    'interface': interface['name'],
                    'address': addr_info['address'],
                    'confidence': 0.0,
                    'reasons': [],
                    'network_type': 'unknown'
                }
                
                # Analyze subnet characteristics
                ip = ipaddress.IPv4Address(addr_info['address'])
                network = ipaddress.IPv4Network(addr_info['subnet'])
                
                # Check if it's a private network
                if ip.is_private:
                    subnet_info['confidence'] += 0.3
                    subnet_info['reasons'].append('Private IP range')
                    
                    # Determine network type based on IP range
                    if str(network.network_address).startswith('10.'):
                        subnet_info['network_type'] = 'enterprise'
                        subnet_info['confidence'] += 0.2
                        subnet_info['reasons'].append('Enterprise network (10.x.x.x)')
                    elif str(network.network_address).startswith('192.168.'):
                        subnet_info['network_type'] = 'local'
                        subnet_info['confidence'] += 0.1
                        subnet_info['reasons'].append('Local network (192.168.x.x)')
                    elif str(network.network_address).startswith('172.'):
                        subnet_info['network_type'] = 'corporate'
                        subnet_info['confidence'] += 0.2
                        subnet_info['reasons'].append('Corporate network (172.x.x.x)')
                
                # Check interface name for clues
                interface_name = interface['name'].lower()
                if any(keyword in interface_name for keyword in ['wifi', 'wlan', 'wireless']):
                    subnet_info['confidence'] += 0.3
                    subnet_info['reasons'].append('Wireless interface detected')
                elif any(keyword in interface_name for keyword in ['eth', 'ethernet', 'lan']):
                    subnet_info['confidence'] += 0.2
                    subnet_info['reasons'].append('Ethernet interface detected')
                
                # Check network size (larger networks more likely to be institutional)
                if network.num_addresses > 1000:
                    subnet_info['confidence'] += 0.2
                    subnet_info['reasons'].append('Large network size')
                elif network.num_addresses > 250:
                    subnet_info['confidence'] += 0.1
                    subnet_info['reasons'].append('Medium network size')
                
                # Add high-confidence subnets
                if subnet_info['confidence'] >= confidence_threshold:
                    suggested_subnets.append(subnet_info)
        
        # Sort by confidence
        suggested_subnets.sort(key=lambda x: x['confidence'], reverse=True)
        
        return suggested_subnets
    
    def auto_configure_subnets(self, apply_changes: bool = False) -> Dict:
        """
        Auto-configure campus subnets based on detection
        
        Args:
            apply_changes: Whether to actually save changes to database
            
        Returns:
            Dictionary with configuration results
        """
        results = {
            'detected_subnets': [],
            'new_subnets': [],
            'existing_subnets': [],
            'recommendations': [],
            'warnings': [],
            'success': False
        }
        
        try:
            # Detect subnets
            detected = self.detect_campus_subnets()
            results['detected_subnets'] = detected
            
            # Check against existing subnets
            existing_subnets = set()
            for campus_subnet in CampusSubnet.objects.filter(is_active=True):
                existing_subnets.add(campus_subnet.subnet)
                results['existing_subnets'].append({
                    'subnet': campus_subnet.subnet,
                    'name': campus_subnet.name,
                    'description': campus_subnet.description
                })
            
            # Find new subnets to add
            for detected_subnet in detected:
                if detected_subnet['subnet'] not in existing_subnets:
                    subnet_name = self._generate_subnet_name(detected_subnet)
                    new_subnet = {
                        'subnet': detected_subnet['subnet'],
                        'name': subnet_name,
                        'description': f"Auto-detected from {detected_subnet['interface']} interface",
                        'confidence': detected_subnet['confidence'],
                        'reasons': detected_subnet['reasons']
                    }
                    results['new_subnets'].append(new_subnet)
                    
                    if apply_changes:
                        try:
                            CampusSubnet.objects.create(
                                name=subnet_name,
                                subnet=detected_subnet['subnet'],
                                description=new_subnet['description'],
                                is_active=True
                            )
                        except Exception as e:
                            results['warnings'].append(f"Failed to create subnet {detected_subnet['subnet']}: {e}")
            
            # Generate recommendations
            results['recommendations'] = self._generate_recommendations(detected)
            
            results['success'] = True
            
        except Exception as e:
            results['warnings'].append(f"Auto-configuration failed: {e}")
        
        return results
    
    def _generate_subnet_name(self, subnet_info: Dict) -> str:
        """Generate a descriptive name for a detected subnet"""
        network_type = subnet_info.get('network_type', 'unknown').title()
        interface = subnet_info.get('interface', 'Unknown')
        
        # Clean up interface name
        if 'wifi' in interface.lower() or 'wlan' in interface.lower():
            interface_type = 'WiFi'
        elif 'eth' in interface.lower():
            interface_type = 'Ethernet'
        else:
            interface_type = 'Network'
        
        return f"{network_type} {interface_type} ({subnet_info['subnet']})"
    
    def _generate_recommendations(self, detected_subnets: List[Dict]) -> List[str]:
        """Generate configuration recommendations"""
        recommendations = []
        
        if not detected_subnets:
            recommendations.append("No subnets detected. Check network connectivity.")
            return recommendations
        
        high_confidence = [s for s in detected_subnets if s['confidence'] > 0.8]
        medium_confidence = [s for s in detected_subnets if 0.5 <= s['confidence'] <= 0.8]
        
        if high_confidence:
            recommendations.append(f"Found {len(high_confidence)} high-confidence subnet(s) - recommend adding immediately.")
        
        if medium_confidence:
            recommendations.append(f"Found {len(medium_confidence)} medium-confidence subnet(s) - review before adding.")
        
        # Check for common institutional patterns
        enterprise_subnets = [s for s in detected_subnets if s.get('network_type') == 'enterprise']
        if enterprise_subnets:
            recommendations.append("Enterprise networks detected - likely institutional WiFi.")
        
        # Security recommendations
        recommendations.append("Review all auto-detected subnets before enabling in production.")
        recommendations.append("Consider adding VPN ranges if remote access is required.")
        
        return recommendations
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def _is_windows(self) -> bool:
        """Check if running on Windows"""
        return self._get_platform() == 'Windows'
    
    def _get_platform(self) -> str:
        """Get platform name"""
        import platform
        return platform.system()
    
    def export_network_info(self, filename: Optional[str] = None) -> str:
        """Export network information to JSON file"""
        if not self.system_info:
            self.get_system_network_info()
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_info_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.system_info, f, indent=2, default=str)
            
            return f"Network information exported to {filename}"
        except Exception as e:
            return f"Failed to export network information: {e}"


def get_current_ip_config() -> Dict:
    """Quick function to get current IP configuration"""
    detector = NetworkDetector()
    return detector.get_system_network_info()


def auto_detect_campus_subnets() -> List[Dict]:
    """Quick function to auto-detect campus subnets"""
    detector = NetworkDetector()
    return detector.detect_campus_subnets()


def suggest_subnet_configuration() -> Dict:
    """Quick function to get subnet configuration suggestions"""
    detector = NetworkDetector()
    return detector.auto_configure_subnets(apply_changes=False)


# Enhanced IP validation with network detection
def validate_ip_with_detection(ip_address: str, auto_add_subnet: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Validate IP address and optionally auto-add detected subnets
    
    Args:
        ip_address: IP address to validate
        auto_add_subnet: Whether to automatically add new subnets if detected
        
    Returns:
        Tuple of (is_valid, subnet_added)
    """
    from .utils import validate_campus_subnet
    
    # First check existing validation
    if validate_campus_subnet(ip_address):
        return True, None
    
    if not auto_add_subnet:
        return False, None
    
    try:
        # Try to detect if this IP belongs to a current network interface
        detector = NetworkDetector()
        interfaces = detector.get_network_interfaces()
        
        user_ip = ipaddress.ip_address(ip_address)
        
        for interface in interfaces:
            if not interface['is_active']:
                continue
                
            for addr_info in interface['addresses']:
                if addr_info['type'] != 'IPv4':
                    continue
                
                network = ipaddress.ip_network(addr_info['subnet'])
                if user_ip in network:
                    # This IP is in a detected network - add the subnet
                    subnet_name = f"Auto-detected from {interface['name']}"
                    
                    try:
                        campus_subnet, created = CampusSubnet.objects.get_or_create(
                            subnet=addr_info['subnet'],
                            defaults={
                                'name': subnet_name,
                                'description': f"Automatically added when validating IP {ip_address}",
                                'is_active': True
                            }
                        )
                        
                        if created:
                            return True, addr_info['subnet']
                        else:
                            return True, None
                    except Exception as e:
                        print(f"Failed to auto-add subnet: {e}")
                        return False, None
        
        return False, None
        
    except Exception as e:
        print(f"Error in IP validation with detection: {e}")
        return False, None
