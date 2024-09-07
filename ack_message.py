from base_message import BaseMessage
from hive_node import HiveNode


class AckMessage(BaseMessage):
    """
    AckMessage represents an acknowledgment message sent between HiveNodes.

    Attributes:
    ----------
    sender : HiveNode
        The node sending the acknowledgment message.
    recipient : HiveNode
        The node receiving the acknowledgment message.
    command : str
        The command type for the acknowledgment message, set to 'ack_message'.
    """

    def __init__(self, sender: HiveNode, recipient: HiveNode):
        """
        Initializes a new instance of AckMessage.

        Parameters:
        ----------
        sender : HiveNode
            The node sending the acknowledgment message.
        recipient : HiveNode
            The node receiving the acknowledgment message.
        """
        super().__init__(sender, recipient, 'ack_message')
