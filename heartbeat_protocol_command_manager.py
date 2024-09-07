import time
from logger import Logger
from hive_message import HiveMessage
from message_queue import MessageQueue
from app_settings import AppSettings
from heartbeat_message import HeartbeatMessage
from hive_node_manager import HiveNodeManager


class HeartbeatProtocolCommandManager:
    """
    HeartbeatProtocolCommandManager manages the heartbeat protocol for the Hive network.

    Attributes:
    ----------
    enable : bool
        A class-level flag to enable or disable the heartbeat protocol.
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
        Initializes a new instance of HeartbeatProtocolCommandManager.

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

        self.logger.debug("HeartbeatProtocolCommandManager", "HeartbeatProtocolCommandManager initialized...")

    def run(self) -> None:
        """
        Starts the heartbeat protocol by periodically sending heartbeat messages to random nodes in the network.
        """
        while True:
            if HeartbeatProtocolCommandManager.enable:
                self.logger.debug("HeartbeatProtocolCommandManager", "Running...")
                random_remote_node = self.hive_node_manager.get_random_live_node()

                if random_remote_node:
                    self.logger.info("HeartbeatProtocolCommandManager", f"Sending heartbeat to {random_remote_node.friendly_name}...")
                    heartbeat_message = HeartbeatMessage(
                        sender=self.hive_node_manager.local_node,
                        recipient=random_remote_node
                    )
                    new_hive_message = HiveMessage(heartbeat_message)
                    self.outbound_message_queue.enqueue(new_hive_message)

            time.sleep(AppSettings.HEARTBEAT_PROTOCOL_FREQUENCY_IN_SECONDS)

    def enable_heartbeat_protocol(self) -> None:
        """
        Enables the heartbeat protocol by setting the appropriate flag.
        """
        self.logger.debug("HeartbeatProtocolCommandManager", "Enabling heartbeat protocol...")
        HeartbeatProtocolCommandManager.enable = True

    def disable_heartbeat_protocol(self) -> None:
        """
        Disables the heartbeat protocol by setting the appropriate flag.
        """
        self.logger.debug("HeartbeatProtocolCommandManager", "Disabling heartbeat protocol...")
        HeartbeatProtocolCommandManager.enable = False
