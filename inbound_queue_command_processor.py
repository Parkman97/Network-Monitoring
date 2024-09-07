import time
import json
import ast

from typing import Dict
from logger import Logger
from hive_message import HiveMessage
from message_queue import MessageQueue
from hive_node import HiveNode
from hive_node_manager import HiveNodeManager
from app_settings import AppSettings
from config_message import ConfigMessage


class InboundQueueCommandProcessor:
    """
    InboundQueueCommandProcessor processes messages from the inbound message queue.
    It handles different types of commands such as 'connect', 'heartbeat', and 'gossip'.

    Attributes:
    ----------
    logger : Logger
        An instance of the Logger class for logging messages.
    hive_node_manager : HiveNodeManager
        An instance of HiveNodeManager for managing the list of nodes.
    outbound_message_queue : MessageQueue
        A queue for storing outgoing messages.
    inbound_message_queue : MessageQueue
        A queue for storing incoming messages.
    """

    def __init__(self, hive_node_manager: HiveNodeManager, outbound_message_queue: MessageQueue, inbound_message_queue: MessageQueue, app_main):
        """
        Initializes a new instance of InboundQueueCommandProcessor.

        Parameters:
        ----------
        hive_node_manager : HiveNodeManager
            An instance of HiveNodeManager for managing the list of nodes.
        outbound_message_queue : MessageQueue
            A queue for storing outgoing messages.
        inbound_message_queue : MessageQueue
            A queue for storing incoming messages.
        """
        self.logger: Logger = Logger()
        self.hive_node_manager = hive_node_manager
        self.outbound_message_queue = outbound_message_queue
        self.inbound_message_queue = inbound_message_queue
        self.app_main = app_main

        self.logger.debug("InboundQueueCommandProcessor", "InboundQueueCommandProcessor initialized...")

    def run(self) -> None:
        """
        Continuously processes messages from the inbound message queue.
        """
        while True:
            message = self.inbound_message_queue.dequeue()
            if message:
                self.process_message(message)
            time.sleep(AppSettings.QUEUE_SEND_SLEEP_IN_SECONDS)

    def process_message(self, hive_message: HiveMessage) -> None:
        """
        Processes a single message from the inbound message queue based on its command.

        Parameters:
        ----------
        hive_message : HiveMessage
            The message to be processed.
        """
        self.logger.debug("InboundQueueCommandProcessor", f"Processing message from {hive_message.message.sender.friendly_name}...")

        self.logger.debug("InboundQueueCommandProcessor", f"Processing Message: {hive_message.message.to_json()}")

        command: str = hive_message.get_json_message_as_dict()['command']
        if command == 'connect':
            self.process_command_connect(hive_message)
        elif command == 'heartbeat':
            self.process_command_heartbeat(hive_message)
        elif command == 'gossip':
            self.process_command_gossip(hive_message)
        elif command == 'config':
            self.process_command_config(hive_message)
        else:
            self.logger.info("InboundQueueCommandProcessor", f"Unknown command in Hive Message: {command}")

    def process_command_connect(self, hive_message: HiveMessage) -> None:
        """
        Processes a 'connect' command, adding the new node to the node manager.

        Parameters:
        ----------
        hive_message : HiveMessage
            The message containing the 'connect' command.
        """
        self.logger.info("InboundQueueCommandProcessor", f"Received connection request from {hive_message.message.sender.friendly_name}...")
        new_hive_node = HiveNode(hive_message.message.sender.friendly_name, hive_message.message.sender.ip_address, int(hive_message.message.sender.port_number))
        self.hive_node_manager.add_node(new_hive_node)
        self.logger.info("InboundQueueCommandProcessor", f"Added {new_hive_node.friendly_name} to the node list...")

        # Send current monitoring config back to requesting node
        config_message: ConfigMessage = ConfigMessage(
            sender=self.hive_node_manager.local_node,
            recipient=new_hive_node,
            message=str(self.app_main.configuration_dict)
        )
        new_hive_message: HiveMessage = HiveMessage(config_message)
        self.outbound_message_queue.enqueue(new_hive_message)

    def process_command_heartbeat(self, hive_message: HiveMessage) -> None:
        """
        Processes a 'heartbeat' command, updating the last heartbeat timestamp for the node.

        Parameters:
        ----------
        hive_message : HiveMessage
            The message containing the 'heartbeat' command.
        """
        self.logger.info("InboundQueueCommandProcessor", f"Received heartbeat from {hive_message.message.sender.friendly_name}...")

        source_friendly_name: str = hive_message.message.sender.friendly_name
        source_ip_address: str = hive_message.message.sender.ip_address
        source_port: int = hive_message.message.sender.port_number

        source_node: HiveNode = self.hive_node_manager.get_node_by_ip_address_and_port(source_ip_address, source_port)

        if source_node:
            self.logger.info("InboundQueueCommandProcessor", f"Found {source_node.friendly_name} in the node list...")
            source_node.set_last_heartbeat_timestamp()
            self.logger.info("InboundQueueCommandProcessor", f"Updated last heartbeat for {source_node.friendly_name}...")
        else:
            self.logger.info("InboundQueueCommandProcessor", f"Adding {source_friendly_name} to the node list...")
            new_hive_node: HiveNode = HiveNode(source_friendly_name, source_ip_address, source_port)
            new_hive_node.set_last_heartbeat_timestamp()
            self.hive_node_manager.add_node(new_hive_node)

    def process_command_gossip(self, hive_message: HiveMessage) -> None:
        """
        Processes a 'gossip' command, updating the node manager with new nodes.

        Parameters:
        ----------
        hive_message : HiveMessage
            The message containing the 'gossip' command.
        """
        self.logger.info("InboundQueueCommandProcessor", f"Received gossip from {hive_message.message.sender.friendly_name}...")
        new_nodes: Dict = hive_message.message.to_json()['nodes']
        for node_friendly_name, node_info in new_nodes.items():
            node_ip_address: str = node_info['ip_address']
            node_port_number: int = node_info['port_number']

            existing_node: HiveNode = self.hive_node_manager.get_node_by_ip_address_and_port(node_ip_address, node_port_number)
            if existing_node:
                self.logger.info("InboundQueueCommandProcessor", f"Found {existing_node.friendly_name} in the node list...")
                existing_node.node_is_alive()
            else:
                self.logger.info("InboundQueueCommandProcessor", f"Adding {node_friendly_name} to the node list...")
                new_hive_node = HiveNode(node_friendly_name, node_ip_address, node_port_number)
                self.hive_node_manager.add_node(new_hive_node)

    def process_command_config(self, hive_message: HiveMessage):
        parsed_dict = self.str_to_dict(hive_message.message.message)
        services = self.str_to_dict(parsed_dict['message'])
      

        # No previous configurations
        if  self.app_main.configuration_dict == {}:
            self.app_main.configuration_dict = services
        
        else:
            current_version = self.app_main.configuration_dict["config"]["version"]
            new_version = services["config"]["version"]

            if current_version < new_version:
                self.app_main.configuration_dict = services
            
            elif current_version == new_version:

                timestamp1 = self.app_main.configuration_dict["config"]["datetime"]
                timestamp2 = services["config"]["datetime"]

                if timestamp1 < timestamp2:
                    self.app_main.configuration_dict = services


        
        self.logger.info('InboundQueueCommandProcessor', f' Updating Configuration to: {self.app_main.configuration_dict}')


    def str_to_dict(self, string_dictionary):
        string_dictionary.replace("'", '"')
        outer_dict = ast.literal_eval(string_dictionary)
        json_str = json.dumps(outer_dict, indent=2)
        parsed_dict = json.loads(json_str)
        return parsed_dict