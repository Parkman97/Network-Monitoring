import time
from logger import Logger
from hive_message import HiveMessage
from message_queue import MessageQueue
from app_settings import AppSettings
from gossip_message import GossipMessage
from hive_node_manager import HiveNodeManager
from typing import Dict


class GossipProtocolCommandManager:
    """
    GossipProtocolCommandManager manages the gossip protocol for the Hive network.

    Attributes:
    ----------
    enable : bool
        A class-level flag to enable or disable the gossip protocol.
    logger : Logger
        An instance of the Logger class for logging messages.
    hive_node_manager : HiveNodeManager
        Manages the nodes in the Hive network.
    outbound_message_queue : MessageQueue
        A queue for outbound messages.
    """

    enable: bool = True

    def __init__(self, hive_node_manager: HiveNodeManager, outbound_message_queue: MessageQueue):
        """
        Initializes a new instance of GossipProtocolCommandManager.

        Parameters:
        ----------
        hive_node_manager : HiveNodeManager
            Manages the nodes in the Hive network.
        outbound_message_queue : MessageQueue
            A queue for outbound messages.
        """
        self.logger: Logger = Logger()
        self.hive_node_manager: HiveNodeManager = hive_node_manager
        self.outbound_message_queue: MessageQueue = outbound_message_queue

        self.logger.debug("GossipProtocolCommandManager", "GossipProtocolCommandManager initialized...")

    def run(self) -> None:
        """
        Starts the gossip protocol by periodically sending gossip messages to random nodes in the network.
        """
        while True:
            if GossipProtocolCommandManager.enable:
                self.logger.debug("GossipProtocolCommandManager", "Running...")

                # Pick a random node
                random_node = self.hive_node_manager.get_random_live_node()

                if random_node:
                    nodes_info: Dict[str, Dict[str, str]] = {
                        node.friendly_name: {'ip_address': node.ip_address, 'port_number': str(node.port_number)}
                        for node in self.hive_node_manager.get_all_live_nodes()
                    }

                    gossip_message: GossipMessage = GossipMessage(
                        sender=self.hive_node_manager.local_node,
                        recipient=random_node,
                        nodes=nodes_info
                    )
                    new_hive_message: HiveMessage = HiveMessage(gossip_message)
                    self.outbound_message_queue.enqueue(new_hive_message)
                else:
                    self.logger.debug("GossipProtocolCommandManager", "No live nodes found...")

            time.sleep(AppSettings.GOSSIP_PROTOCOL_FREQUENCY_IN_SECONDS)

    def enable_gossip_protocol(self) -> None:
        """
        Enables the gossip protocol by setting the appropriate flag.
        """
        self.logger.debug("GossipProtocolCommandManager", "Enabling gossip protocol...")
        GossipProtocolCommandManager.enable = True

    def disable_gossip_protocol(self) -> None:
        """
        Disables the gossip protocol by setting the appropriate flag.
        """
        self.logger.debug("GossipProtocolCommandManager", "Disabling gossip protocol...")
        GossipProtocolCommandManager.enable = False
