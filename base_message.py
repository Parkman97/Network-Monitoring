import json
from hive_node import HiveNode
from typing import Dict


class BaseMessage:
    """
    BaseMessage is the base class for all message types exchanged between HiveNodes.

    Attributes:
    ----------
    sender : HiveNode
        The node sending the message.
    recipient : HiveNode
        The node receiving the message.
    command : str
        The command type of the message.
    """

    def __init__(self, sender: HiveNode, recipient: HiveNode, command: str):
        """
        Initializes a new instance of BaseMessage.

        Parameters:
        ----------
        sender : HiveNode
            The node sending the message.
        recipient : HiveNode
            The node receiving the message.
        command : str
            The command type of the message.
        """
        self.sender: HiveNode = sender
        self.recipient: HiveNode = recipient
        self.command: str = command

    def to_dict(self) -> Dict[str, str]:
        """
        Converts the BaseMessage to a dictionary.

        Returns:
        -------
        Dict[str, str]
            A dictionary representation of the message.
        """
        return {
            'command': self.command,
            'source_friendly_name': self.sender.friendly_name,
            'source_ip_address': self.sender.ip_address,
            'source_port': self.sender.port_number,
            'destination_friendly_name': self.recipient.friendly_name,
            'destination_ip_address': self.recipient.ip_address,
            'destination_port': self.recipient.port_number,
        }

    def to_json(self) -> str:
        """
        Converts the BaseMessage to a JSON string.

        Returns:
        -------
        str
            A JSON string representation of the message.
        """
        return json.dumps(self.to_dict())
