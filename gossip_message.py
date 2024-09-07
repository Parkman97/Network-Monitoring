from base_message import BaseMessage
from hive_node import HiveNode
from typing import Dict


class GossipMessage(BaseMessage):
    """
    GossipMessage represents a message for gossip protocol in the Hive network.

    Attributes:
    ----------
    sender : HiveNode
        The sender node of the message.
    recipient : HiveNode
        The recipient node of the message.
    nodes : Dict[str, dict]
        A dictionary containing information about other nodes in the network.
    """

    def __init__(self, sender: HiveNode, recipient: HiveNode, nodes: Dict[str, dict], updated_config=None):
        """
        Initializes a new instance of GossipMessage.

        Parameters:
        ----------
        sender : HiveNode
            The sender node of the message.
        recipient : HiveNode
            The recipient node of the message.
        nodes : Dict[str, dict]
            A dictionary containing information about other nodes in the network.
        """
        if updated_config == None:
            super().__init__(sender, recipient, 'gossip')
            self.nodes: Dict[str, dict] = nodes
        else:
            super().__init__(sender, recipient, 'updated_config')
            
    def to_dict(self) -> Dict[str, dict]:
        """
        Converts the GossipMessage instance to a dictionary representation.

        Returns:
        -------
        Dict[str, dict]
            A dictionary representing the GossipMessage instance.
        """
        base_dict: Dict[str, dict] = super().to_dict()
        base_dict.update({'nodes': self.nodes})
        return base_dict
