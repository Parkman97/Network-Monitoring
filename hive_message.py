import json
from base_message import BaseMessage
from typing import Dict


class HiveMessage:
    """
    HiveMessage is a wrapper for messages that will be sent between nodes.
    It includes the message content, as well as a count of how many times the message has been sent.

    Attributes:
    ----------
    message : BaseMessage
        The actual message content to be sent between nodes.
    send_attempt_count : int
        The number of attempts made to send this message.
    """

    def __init__(self, message: BaseMessage):
        """
        Initializes a new instance of HiveMessage.

        Parameters:
        ----------
        message : BaseMessage
            The actual message content to be sent between nodes.
        """
        self.message: BaseMessage = message
        self.send_attempt_count: int = 0

    def get_json_message_as_dict(self) -> Dict:
        """
        Converts the message content to a dictionary format suitable for deserialization.

        Returns:
        -------
        Dict
            A dictionary representation of the message content.
        """
        return json.loads(self.message.to_json())
