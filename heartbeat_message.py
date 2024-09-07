from base_message import BaseMessage
from hive_node import HiveNode
from typing import Dict


class HeartbeatMessage(BaseMessage):
    """
    HeartbeatMessage represents a message for the heartbeat protocol in the Hive network.

    Attributes:
    ----------
    sender : HiveNode
        The sender node of the message.
    recipient : HiveNode
        The recipient node of the message.
    """

    def __init__(self, sender: HiveNode, recipient: HiveNode):
        """
        Initializes a new instance of HeartbeatMessage.

        Parameters:
        ----------
        sender : HiveNode
            The sender node of the message.
        recipient : HiveNode
            The recipient node of the message.
        """
        super().__init__(sender, recipient, 'heartbeat')

    def to_dict(self) -> Dict[str, str]:
        """
        Converts the HeartbeatMessage instance to a dictionary representation.

        Returns:
        -------
        Dict[str, str]
            A dictionary representing the HeartbeatMessage instance.
        """
        base_dict: Dict[str, str] = super().to_dict()
        return base_dict
