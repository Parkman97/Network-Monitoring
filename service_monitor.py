import threading
import time
import socket
import requests
import ntplib
import ping3 
import dns.resolver
import datetime

from logger import Logger
from time import ctime
from socket import gaierror
from typing import Tuple, Optional
from app_settings import AppSettings

current_config = None
stop_events = []

class ServiceMonitoring:
    """
    HiveReceiverService is responsible for handling incoming and outgoing network connections.
    It listens for connections from other nodes, processes incoming messages, and sends acknowledgments.

    Attributes:
    ----------
    logger : Logger
        An instance of the Logger class for logging messages.
    name : str
        The name of the HiveReceiverService instance.
    ip_address : str
        The IP address on which the service listens.
    port : int
        The port number on which the service listens.
    hive_node_manager : HiveNodeManager
        An instance of HiveNodeManager for managing the list of nodes.
    inbound_message_queue : MessageQueue
        A queue for storing incoming messages.
    outbound_message_queue : MessageQueue
        A queue for storing outgoing messages.
    """

    def __init__(self, appMain):
        """
        Initializes a new instance of service_monitor
        """
        self.logger: Logger = Logger()
        self.appMain = appMain
        self.logger.debug("HiveReceiverService", "HiveReceiverService initialized...")

    def run(self) -> None:
        """
        Starts the HiveReceiverService, listening for incoming connections and handling them in separate threads.
        """
        global current_config
        while True:

            if self.appMain.configuration_dict == {}:
                self.logger.info("Service Monitoring", "Waiting for configuration file")
            else:
                
                if current_config is None:
                    print('First time through with actual dictionary')
                    self.create_results_dict()
                    current_config = self.appMain.configuration_dict
                    self.thread_handling(self.appMain.configuration_dict)

                # Only updates service monitors if this cities entries were updated
                elif current_config["config"]["Services"][self.appMain.name] != self.appMain.configuration_dict["config"]["Services"][self.appMain.name]:
                    print('Update happened to config and need to update')
                    self.create_results_dict()
                    current_config = self.appMain.configuration_dict
                    self.thread_handling(self.appMain.configuration_dict, True)
            
            time.sleep(10)

    def thread_handling(self, config_dict, update=False) -> None:
        """
        Main function to handle user input and manage threads.
        Uses prompt-toolkit for handling user input with auto-completion and ensures
        the prompt stays at the bottom of the terminal.
        """
        global stop_events
        if update:
            while stop_events:
                event = stop_events.pop(0)
                event.set()

        city_services = config_dict["config"]["Services"][self.appMain.name]
        # Event to signal the worker thread to stop
        stop_event: threading.Event = threading.Event()
        stop_events.append(stop_event)

        # Create and start the worker thread
        thread = None
        for service in city_services:
            if service == 'ECHO':
                thread: threading.Thread = threading.Thread(target=self.check_echo_server, args=(stop_event, city_services[service]))
                
            elif service  == 'HTTP' or service  == 'HTTPS' :
                thread: threading.Thread = threading.Thread(target=self.check_http_request, args=(stop_event, city_services[service], service))
                
            elif service  == "ICMP":
                thread: threading.Thread = threading.Thread(target=self.check_icmp, args=(stop_event, city_services[service]))
            
            elif service  == "DNS":
                thread: threading.Thread = threading.Thread(target=self.check_dns, args=(stop_event,city_services[service]))
            
            elif service  == "TCP":
                thread: threading.Thread = threading.Thread(target=self.check_tcp, args=(stop_event, city_services[service]))
                
            elif service  == 'UDP':
                thread: threading.Thread = threading.Thread(target=self.check_udp, args=(stop_event, city_services[service]))
        
            elif service  == 'NTP':
                thread: threading.Thread = threading.Thread(target=self.check_ntp, args=(stop_event, city_services[service]))
            thread.start()

    def socket_creation(self, protocol, ip_address, port, message=None):
        """
        Attempts to establish either a TCP connection or send a UDP packet(based on input params) to the specified 
        port on the given IP address. For TCP If the connection is successful, it means the port is open; otherwise, 
        the port is considered closed or unreachable. Since UDP is a connectionless protocol, the function can't definitively 
        determine if the port is open. It can only confirm if the port is closed, typically indicated by an ICMP 
        'Destination Unreachable' response.

        Args:
        protocol (str): The type of socket you wish to communicate over (TCP or UDP) 
        ip_address (str): The IP Address of the target Host 
        port (int): Port number you wish to communicate on 

        :return: None
        """
        timestamp = datetime.datetime.now().strftime(AppSettings.TIMESTAMP_FORMAT)
        if protocol == "TCP":
            try:
                # Create a socket object using the AF_INET address family (IPv4) and SOCK_STREAM socket type (TCP).
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    # Set a timeout for the socket to avoid waiting indefinitely. Here, 3 seconds is used as a reasonable timeout duration.
                    s.settimeout(3)
                    # Attempt to connect to the specified IP address and port.
                    # If the connection is successful, the port is open.
                    s.connect((ip_address, port))

                    if message != "":
                        self.logger.info("Service Monitoring", f"Sending to Echo Server: {message}")
                        s.send(message.encode())

                        response = s.recv(1024)
                        self.logger.info("Service Monitoring", f'TCP - Received from Echo Server: {response.decode()}')

                    self.logger.info("Service Monitoring", f"TCP can communicate on Port {port} with {ip_address}.")
                    self.appMain.results_dict[self.appMain.name][protocol] = f"[{timestamp}] TCP can communicate on Port {port} with {ip_address}."

            except socket.timeout:
                # If a timeout occurs, it means the connection attempt took too long, implying the port might be filtered or the server is slow to respond.
                self.logger.info("Service Monitoring", f"Port {port} on {ip_address} timed out.")
                self.appMain.results_dict[self.appMain.name][protocol] = f"[{timestamp}] Port {port} on {ip_address} timed out."

            except socket.error:
                # If a socket error occurs, it generally means the port is closed or not reachable.
                self.logger.info("Service Monitoring", f"Port {port} on {ip_address} is closed or not reachable.")
                self.appMain.results_dict[self.appMain.name][protocol] = f"[{timestamp}] Port {port} on {ip_address} is closed or not reachable."

            except Exception as e:
                # Catch any other exceptions and return a general failure message along with the exception raised.
                self.logger.info("Service Monitoring", f"Failed to check port {port} wit {ip_address} due to an error: {e}")
                self.appMain.results_dict[self.appMain.name][protocol] = f"[{timestamp}] Failed to check port {port} wit {ip_address} due to an error: {e}"
        
        elif protocol == "UDP":
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(5)
                s.sendto(message, (ip_address, port))
                try:
                    s.recvfrom(1024)
                    self.logger.info("Service Monitoring", f"Port {port} on {ip_address} is closed.")
                    self.appMain.results_dict[self.appMain.name][protocol] = f"[{timestamp}] Port {port} on {ip_address} is closed."
                    

                except socket.timeout:
                    # If a timeout occurs, it's uncertain whether the port is open or closed, as no response is received.
                    self.logger.info("Service Monitoring", f"UDP can communicate on Port {port} with {ip_address} is open or no response received.")
                    self.appMain.results_dict[self.appMain.name][protocol] = f"[{timestamp}] UDP can communicate on Port {port} with {ip_address} is open or no response received."
                    
                finally:
                    s.close()
            except Exception as e:
                # Catch any other exceptions and return a general failure message along with the exception raised.
                self.logger.info("Service Monitoring", f"Failed to check UDP port {port} on {ip_address} due to an error: {e}")
                self.appMain.results_dict[self.appMain.name][protocol] = f"[{timestamp}] Failed to check port {port} wit {ip_address} due to an error: {e}"

        else:
            self.logger.info("Service Monitoring", 'Incorrect protocol given')

    
    def check_icmp(self, stop_event: threading.Event, service_dict:dict) -> None:
        """
        Sends a Echo Request to a specified HOST and measures the Round Trip Time

        This function utilizes the socket module to get the host name and the ping3 
        module to send a ping to said host. It waits for an echo reply and prints out
        the round trip time and the IP address of the host.

        Args:
        host (str): The IP address or hostname of the target host.

        :return: None
        """
        timestamp = datetime.datetime.now().strftime(AppSettings.TIMESTAMP_FORMAT)
        host = service_dict["target"]
        frequency = service_dict["interval"]

        while not stop_event.is_set():
            ip_address = socket.gethostbyname(host)
            response = ping3.ping(host)
            if response is None:
                self.logger.info("Service Monitoring", "Ping Failed")
                self.appMain.results_dict[self.appMain.name]['ICMP'] = timestamp + 'Ping Failed'
            else:
                self.logger.info("Service Monitoring", f"Ping (Echo Request) successful. Response Time= {ip_address}, Round-trip time: {response} ms")
                self.appMain.results_dict[self.appMain.name]['ICMP'] = f" [{timestamp}] Ping (Echo Request) successful. Response Time= {ip_address}, Round-trip time: {response} ms"
            time.sleep(frequency)
        

    # echo_server thread function
    def check_echo_server(self, stop_event: threading.Event, service_dict:dict) -> None:
        """
        Sends a Echo Request to the Echo server which is running locally to make sure its functional

        This function calls for a socket to be created with a specified host, port and message to be sent.

        Args:
        host (str): The IP address or hostname of the target host.

        :return: None
        """
        host = service_dict["target"]
        frequency = service_dict["interval"]

        while not stop_event.is_set():
            port = 12345
            message = 'Echo Server is Awake'
            self.socket_creation("TCP", host, port, message)
            time.sleep(frequency)

    # Other pings thread function
    def check_http_request(self, stop_event: threading.Event, service_dict:dict, protocol) -> None:
        """
        Check if an HTTP/HTTPS server is up by making a request to the provided URL.

        This function attempts to connect to a web server using the specified URL.
        It doesn't return anything but prints whether the request was successful or not

        :param protocol (str): Name of protocol either HTTP or HTTPS
        :param url (str): URL of the server 

        :return: None
        """
        timestamp = datetime.datetime.now().strftime(AppSettings.TIMESTAMP_FORMAT)
        host = service_dict["target"]
        frequency = service_dict["interval"]

        try:
            headers: dict = {'User-Agent': 'Mozilla/5.0'}
            if protocol == "HTTP":
                url = f"http://{host}"
            else:
                url = f"https://{host}"

            while not stop_event.is_set():
                response = requests.get(url, headers, timeout=10)
                if response.status_code < 400:
                    self.logger.info("Service Monitoring", f"Successfully {host} Connection to {host}. Status Code : {response.status_code}")
                    self.appMain.results_dict[self.appMain.name][protocol] = f"[{timestamp}] Successfully {host} Connection to {host}. Status Code : {response.status_code}"
                else:
                    self.logger.info("Service Monitoring", f"Error: {response.status_code}")
                    self.appMain.results_dict[self.appMain.name][protocol] = f"[{timestamp}] Error: {response.status_code}"
                    
                time.sleep(frequency)

        except requests.ConnectionError:
            # This exception is raised for network-related errors, like DNS failure or refused connection.
            self.logger.info("Service Monitoring", "Connection error")
            self.appMain.results_dict[self.appMain.name][protocol] =  f"[{timestamp}] Connection error"

        except requests.Timeout:
            # This exception is raised if the server does not send any data in the allotted time (specified by timeout).
            self.logger.info("Service Monitoring", "Timeout occurred")
            self.appMain.results_dict[self.appMain.name][protocol] =  f"[{timestamp}] Timeout occurred"

        except requests.RequestException as e:
            # A catch-all exception for any error not covered by the specific exceptions above.
            # 'e' contains the details of the exception.
            self.logger.info("Service Monitoring", f"Error during request: {e}")
            self.appMain.results_dict[self.appMain.name][protocol] =  f"[{timestamp}] Error during request: {e}"

    # Other pings thread function
    def check_tcp(self, stop_event: threading.Event, service_dict:dict) -> None:
        """
        Checks the status of a specific TCP port on a given IP address.

        Args:
        server_address (str): The IP address of the target server.
        server_port (int): The TCP port number to check.

        Returns: None

        Description:
        This function continuously monitors the status of a TCP service running on a specified server address 
        and port. It periodically creates a TCP socket connection to the target server using the provided 
        server address and port number.

        return: None
    """
        host = service_dict["target"]
        port = service_dict["port"]
        frequency = service_dict["interval"]

        while not stop_event.is_set():
            self.socket_creation('TCP', host, port)
            time.sleep(frequency)

    # Other pings thread function
    def check_dns(self, stop_event: threading.Event, service_dict:dict) -> None:
        """
        Check if a DNS server is up and prints the DNS query results for a specified domain and record type.

        :param server: DNS server name or IP address
        :param query: Domain name to query
        :param record_type: Type of DNS record (e.g., 'A', 'AAAA', 'MX', 'CNAME')
        :return: None
        """
        timestamp = datetime.datetime.now().strftime(AppSettings.TIMESTAMP_FORMAT)
        host = service_dict["target"]
        domain = service_dict["queries"]["domain"]
        record_type = service_dict["queries"]["type"]
        frequency = service_dict["interval"]
        while not stop_event.is_set():
            try:
                # Set the DNS resolver to use the specified server
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [socket.gethostbyname(host)]

                # Perform a DNS query for the specified domain and record type
                query_results = resolver.resolve(domain, record_type)
                results = [str(rdata) for rdata in query_results]

                self.logger.info("Service Monitoring", f"DNS Server is up results: {results}")
                self.appMain.results_dict[self.appMain.name]['DNS'] =  f"[{timestamp}] DNS Server connection Succeessful"

            except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer, socket.gaierror) as e:
                # Return False if there's an exception (server down, query failed, or record type not found)
                self.logger.info("Service Monitoring", f"DNS Server is down due to {str(e)}")
                self.appMain.results_dict[self.appMain.name]['DNS'] =  f"[{timestamp}] DNS Server connection Unsuccessful"
        
            time.sleep(frequency)

    # Other pings thread function
    def check_udp(self, stop_event: threading.Event, service_dict:dict) -> None:
        """
        Description:
        This function continuously monitors the status of a UDP service running on a specified 
        server address and port. It periodically creates a UDP socket connection to the target 
        server using the provided server address and port number.

        Args:
        server_address (str): The IP address of the target server.
        server_port (int): The UDP port number to check.
        message(binary str): Message you want to send

        Returns: None 
        """

        host = service_dict["target"]
        port = service_dict["port"]
        frequency = service_dict["interval"]

        while not stop_event.is_set():
            self.socket_creation('UDP', host, port, b'Hello World')
            time.sleep(frequency)

    def check_ntp(self, stop_event: threading.Event, service_dict:dict) -> Tuple[bool, Optional[str]]:
        """
        Checks if an NTP server is up and returns its status and time.

        Args:
        server (str): The hostname or IP address of the NTP server to check.

        Returns:
        Tuple[bool, Optional[str]]: A tuple containing a boolean indicating the server status
                                    (True if up, False if down) and the current time as a string
                                    if the server is up, or None if it's down.
        """
        timestamp = datetime.datetime.now().strftime(AppSettings.TIMESTAMP_FORMAT)
        host = service_dict["target"]

        while not stop_event.is_set():
            # Create an NTP client instance
            client = ntplib.NTPClient()

            try:
                # Request time from the NTP server
                # 'version=3' specifies the NTP version to use for the request
                response = client.request(host, version=3)

                # If request is successful, return True and the server time
                # 'ctime' converts the time in seconds since the epoch to a readable format
                self.logger.info("Service Monitoring", f"NTP Request Successful. Time = {ctime(response.tx_time)}")
                self.appMain.results_dict[self.appMain.name]['NTP'] =  f"[{timestamp}] NTP Request Successful. Time = {ctime(response.tx_time)}"
            except (ntplib.NTPException, gaierror):
                # If an exception occurs (server is down or unreachable), return False and None
                self.logger.info("Service Monitoring", "NTP Server is down")
                self.appMain.results_dict[self.appMain.name]['NTP'] = f"[{timestamp}] NTP Server is down"
            time.sleep(120)

        
    def create_results_dict(self):
        """ Creates a results dictioanry based off of the current configuration"""
        self.logger.info("Service Monitoring", self.appMain.configuration_dict["config"]["Services"] )
        for city in self.appMain.configuration_dict["config"]["Services"]:
            self.appMain.results_dict[city] = {}
            for service in self.appMain.configuration_dict["config"]["Services"][city]:
                self.appMain.results_dict[city][service] = None

                