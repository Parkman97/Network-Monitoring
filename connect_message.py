from base_message import BaseMessage
from hive_node import HiveNode


class ConnectMessage(BaseMessage):
    """
    ConnectMessage represents a message for connecting to a new node in the Hive network.

    Attributes:
    ----------
    sender : HiveNode
        The sender node of the message.
    recipient : HiveNode
        The recipient node of the message.
    message : str
        The message content for the connection request.
    """

    def __init__(self, sender: HiveNode, recipient: HiveNode, message: str):
        """
        Initializes a new instance of ConnectMessage.

        Parameters:
        ----------
        sender : HiveNode
            The sender node of the message.
        recipient : HiveNode
            The recipient node of the message.
        message : str
            The message content for the connection request.
        """
        super().__init__(sender, recipient, 'connect')
        self.message: str = message

    def to_dict(self) -> dict:
        """
        Converts the ConnectMessage instance to a dictionary representation.

        Returns:
        -------
        dict
            A dictionary representing the ConnectMessage instance.
        """
        base_dict: dict = super().to_dict()
        base_dict.update({'message': self.message})
        return base_dict
