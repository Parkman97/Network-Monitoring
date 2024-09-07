import json
import socket
import threading
from typing import Tuple, Dict
from logger import Logger
from hive_node import HiveNode
from hive_message import HiveMessage
from message_queue import MessageQueue
from ack_message import AckMessage
from connect_message import ConnectMessage
from config_message import ConfigMessage
from heartbeat_message import HeartbeatMessage


class HiveReceiverService:
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

    def __init__(self, name: str, ip_address: str, port: int, hive_node_manager, inbound_message_queue: MessageQueue, outbound_message_queue: MessageQueue):
        """
        Initializes a new instance of HiveReceiverService.

        Parameters:
        ----------
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
        self.logger: Logger = Logger()
        self.name: str = name
        self.ip_address: str = ip_address
        self.port: int = port
        self.hive_node_manager = hive_node_manager
        self.inbound_message_queue: MessageQueue = inbound_message_queue
        self.outbound_message_queue: MessageQueue = outbound_message_queue

        self.logger.debug("HiveReceiverService", "HiveReceiverService initialized...")

    def run(self) -> None:
        """
        Starts the HiveReceiverService, listening for incoming connections and handling them in separate threads.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.ip_address, self.port))
            server_socket.listen()

            self.logger.info("HiveReceiverService", "HiveReceiverService is running...")
            while True:
                client_socket, client_address = server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True)
                client_thread.start()

    def handle_client(self, client_socket: socket.socket, client_address: Tuple[str, int]) -> None:
        """
        Handles an incoming client connection, reading and processing data from the client.

        Parameters:
        ----------
        client_socket : socket.socket
            The socket representing the client connection.
        client_address : Tuple[str, int]
            The address of the client.
        """
        self.logger.info("HiveReceiverService", f"Connection from {client_address}")
        with client_socket:
            while True:
                data = client_socket.recv(2048)
                if not data:
                    break

                self.logger.debug("HiveReceiverService", f"Data Received: {data.decode()}")

                # Deserialize JSON data to dictionary
                data_dict: Dict = json.loads(data.decode())
                command = data_dict.get('command')

                sender_node = HiveNode(
                    friendly_name=data_dict['source_friendly_name'],
                    ip_address=data_dict['source_ip_address'],
                    port_number=int(data_dict['source_port'])
                )

                if command == 'connect':
                    self.handle_connect(data_dict, sender_node)
                elif command == 'ack_message':
                    self.handle_ack(data_dict, sender_node)
                elif command == 'heartbeat':
                    self.handle_heartbeat(data_dict, sender_node)
                elif command == 'gossip':
                    self.handle_gossip(data_dict, sender_node)
                elif command == 'config':
                    self.handle_config(data_dict, sender_node)
                else:
                    self.logger.warning("HiveReceiverService", f"Unknown command: {command}")

                # Send acknowledgment message
                ack_message = AckMessage(self.hive_node_manager.local_node, sender_node)
                client_socket.sendall(ack_message.to_json().encode())

    def handle_connect(self, data_dict: Dict, sender_node: HiveNode) -> None:
        """
        Handles an incoming 'connect' message, creating a ConnectMessage and enqueuing it in the inbound message queue.

        Parameters:
        ----------
        data_dict : Dict
            The dictionary containing the data from the incoming message.
        sender_node : HiveNode
            The node that sent the connect message.
        """
        connect_message = ConnectMessage(sender_node, self.hive_node_manager.local_node, data_dict.get('message', 'Hello'))
        new_hive_message = HiveMessage(connect_message)
        self.inbound_message_queue.enqueue(new_hive_message)

        self.logger.info("HiveReceiverService", f"Handled connect from {sender_node.friendly_name}")

    def handle_ack(self, data_dict: Dict, sender_node: HiveNode) -> None:
        """
        Handles an incoming 'ack_message', logging the acknowledgment.

        Parameters:
        ----------
        data_dict : Dict
            The dictionary containing the data from the incoming message.
        sender_node : HiveNode
            The node that sent the acknowledgment message.
        """
        self.logger.info("HiveReceiverService", "Acknowledgment received")

    def handle_heartbeat(self, data_dict: Dict, sender_node: HiveNode) -> None:
        """
        Handles an incoming 'heartbeat' message, creating a HeartbeatMessage and enqueuing it in the inbound message queue.

        Parameters:
        ----------
        data_dict : Dict
            The dictionary containing the data from the incoming message.
        sender_node : HiveNode
            The node that sent the heartbeat message.
        """
        heartbeat_message = HeartbeatMessage(sender_node, self.hive_node_manager.local_node)
        new_hive_message = HiveMessage(heartbeat_message)
        self.inbound_message_queue.enqueue(new_hive_message)

        self.logger.info("HiveReceiverService", f"Handled heartbeat from {sender_node.friendly_name}")

    def handle_gossip(self, data_dict: Dict, sender_node: HiveNode) -> None:
        """
        Handles an incoming 'gossip' message, updating the node manager with any new nodes and logging the information.

        Parameters:
        ----------
        data_dict : Dict
            The dictionary containing the data from the incoming message.
        sender_node : HiveNode
            The node that sent the gossip message.
        """
        nodes = data_dict.get('nodes', {})
        for node_name, node_info in nodes.items():
            new_node = HiveNode(
                friendly_name=node_name,
                ip_address=node_info['ip_address'],
                port_number=int(node_info['port_number'])
            )
            if new_node != self.hive_node_manager.local_node:
                self.hive_node_manager.add_node(new_node)

        self.logger.info("HiveReceiverService", f"Handled gossip from {sender_node.friendly_name}")
    
    def handle_config(self, data_dict: Dict, sender_node: HiveNode):
        # Send current monitoring config back to requesting node
        config_message: ConfigMessage = ConfigMessage(
            sender=self.hive_node_manager.local_node,
            recipient=sender_node,
            message=str(data_dict)
        )
        new_hive_message: HiveMessage = HiveMessage(config_message)
        self.inbound_message_queue.enqueue(new_hive_message)
