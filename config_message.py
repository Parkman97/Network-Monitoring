from base_message import BaseMessage
from hive_node import HiveNode


class ConfigMessage(BaseMessage):
    """
    ConfigMessage represents a message for sending the current config to a new node in the Hive network.

    Attributes:
    ----------
    sender : HiveNode
        The sender node of the message.
    recipient : HiveNode
        The recipient node of the message.
    message : str
        The current config of the node that go connected to.
    """

    def __init__(self, sender: HiveNode, recipient: HiveNode, message: str):
        """
        Initializes a new instance of ConfigMessage.

        Parameters:
        ----------
        sender : HiveNode
            The sender node of the message.
        recipient : HiveNode
            The recipient node of the message.
        message : str
            The current config of the node that go connected to.

        """
        super().__init__(sender, recipient, 'config')
        self.message: str = message

    def to_dict(self) -> dict:
        """
        Converts the ConfigMessage instance to a dictionary representation.

        Returns:
        -------
        dict
            A dictionary representing the ConfigMessage instance.
        """
        base_dict: dict = super().to_dict()
        base_dict.update({'message': self.message})
        return base_dict
