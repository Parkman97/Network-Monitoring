import argparse
import datetime
import json
import threading

from typing import Optional
from logger import Logger
from hive_node import HiveNode
from message_queue import MessageQueue
from hive_node_manager import HiveNodeManager
from hive_receiver_service import HiveReceiverService
from hive_sender_client import HiveSenderClient
from cli_command_processor import CliCommandProcessor
from inbound_queue_command_processor import InboundQueueCommandProcessor
from gossip_protocol_command_manager import GossipProtocolCommandManager
from heartbeat_protocol_command_manager import HeartbeatProtocolCommandManager
from app_settings import AppSettings
from service_monitor import ServiceMonitoring



class AppMain:
    """
    AppMain is the main entry point for the Hive network application.

    Attributes:
    ----------
    logger : Logger
        An instance of the Logger class for logging messages.
    cli_command_processor : Optional[CliCommandProcessor]
        An instance of the CliCommandProcessor for processing CLI commands.
    outbound_message_queue : MessageQueue
        A queue for outbound messages.
    inbound_message_queue : MessageQueue
        A queue for inbound messages.
    hive_node_manager : Optional[HiveNodeManager]
        Manages the nodes in the Hive network.
    """

    def __init__(self):
        """
        Initializes a new instance of AppMain.
        """
        self.logger: Logger = Logger()
        self.cli_command_processor: Optional[CliCommandProcessor] = None
        self.outbound_message_queue: MessageQueue = MessageQueue("Outbound")
        self.inbound_message_queue: MessageQueue = MessageQueue("Inbound")
        self.hive_node_manager: Optional[HiveNodeManager] = None
        self.name = None
        self.configuration_dict = {}
        self.results_dict = {}
    

    def run(self) -> None:
        """
        Starts the Hive network application by parsing arguments, setting up the local node,
        and initializing various components such as the Hive service, client, and command processors.
        """
        parser = argparse.ArgumentParser(description='Start a TCP server.')
        parser.add_argument('-ip', type=str, default=AppSettings.DEFAULT_IP_ADDRESS, help='IP address to bind the server')
        parser.add_argument('-port', type=int, default=AppSettings.DEFAULT_PORT_NUMBER, help='Port to bind the server')
        parser.add_argument('-friendly_name', type=str, default=AppSettings.DEFAULT_FRIENDLY_NAME, help='Friendly name for the local node')
        parser.add_argument('-main', type=str, default=AppSettings.DEFAULT_MAIN, help='Node to grab config data')
        args = parser.parse_args()

        # Update Name
        self.name = args.friendly_name

        # Grabs initial configuration
        if args.main.lower() == 'yes':
            self.grab_monitor_config()
        
        # Set the log file name based on the friendly_name
        log_file_name = f"app.{args.friendly_name.replace(' ', '_')}.log"
        self.logger.set_log_file(log_file_name)

        self.logger.debug("AppMain", f"Arguments: {args}")

        local_node: HiveNode = HiveNode(args.friendly_name, args.ip, args.port, is_local_node=True)

        # Hive Node Manager
        self.hive_node_manager = HiveNodeManager(local_node)

        # Hive service server thread
        hive_service = HiveReceiverService(local_node.friendly_name, local_node.ip_address, local_node.port_number, self.hive_node_manager, self.inbound_message_queue, self.outbound_message_queue)
        hive_service_thread = threading.Thread(target=hive_service.run, daemon=True)
        hive_service_thread.start()

        # Hive client thread
        hive_client = HiveSenderClient(self.outbound_message_queue, self.inbound_message_queue)
        hive_client_thread = threading.Thread(target=hive_client.run, daemon=True)
        hive_client_thread.start()

        # Queue Command Processor
        inbound_queue_command_processor = InboundQueueCommandProcessor(self.hive_node_manager, self.outbound_message_queue, self.inbound_message_queue, self)
        inbound_queue_command_processor_thread = threading.Thread(target=inbound_queue_command_processor.run, daemon=True)
        inbound_queue_command_processor_thread.start()

        # Gossip Protocol Command Manager
        gossip_protocol_command_manager = GossipProtocolCommandManager(self.hive_node_manager, self.outbound_message_queue)
        gossip_protocol_command_manager_thread = threading.Thread(target=gossip_protocol_command_manager.run, daemon=True)
        gossip_protocol_command_manager_thread.start()

        # Heartbeat Protocol Command Manager
        heartbeat_protocol_command_manager = HeartbeatProtocolCommandManager(self.hive_node_manager, self.outbound_message_queue)
        heartbeat_protocol_command_manager_thread = threading.Thread(target=heartbeat_protocol_command_manager.run, daemon=True)
        heartbeat_protocol_command_manager_thread.start()

         # Service Monitoring
        service_monitor = ServiceMonitoring(self)
        service_monitor_thread = threading.Thread(target=service_monitor.run, daemon=True)
        service_monitor_thread.start()

        # CLI Command Processor
        self.cli_command_processor = CliCommandProcessor(self.hive_node_manager, self.outbound_message_queue, self.inbound_message_queue, self)
        self.cli_command_processor.set_prompt(f"{local_node.friendly_name}> ")
        self.cli_command_processor.command_loop()

    def grab_monitor_config(self):
        """Grabs the initial configuration from a file"""
        timestamp = datetime.datetime.now().strftime(AppSettings.TIMESTAMP_FORMAT)
        with open('configuration.json', 'r') as file:
            json_data = json.load(file)
        
        # Updates timestamp to current time
        json_data['config']['datetime'] = timestamp

        self.configuration_dict = json_data


if __name__ == "__main__":
    app = AppMain()
    app.run()
