from typing import List, Optional
from logger import Logger
from hive_message import HiveMessage
from app_settings import AppSettings


class MessageQueue:
    """
    MessageQueue manages a queue of HiveMessage objects for processing inbound and outbound messages.

    Attributes:
    ----------
    logger : Logger
        An instance of the Logger class for logging messages.
    queue_name : str
        The name of the queue.
    queue : List[HiveMessage]
        A list to store HiveMessage objects.
    """

    def __init__(self, queue_name: str):
        """
        Initializes a new instance of MessageQueue.

        Parameters:
        ----------
        queue_name : str
            The name of the queue.
        """
        self.logger: Logger = Logger()
        self.queue_name: str = queue_name
        self.queue: List[HiveMessage] = []

    def enqueue(self, hive_message: HiveMessage) -> None:
        """
        Adds a HiveMessage to the queue.

        Parameters:
        ----------
        hive_message : HiveMessage
            The message to be added to the queue.
        """
        self.logger.debug("MessageQueue", f"Adding message to {self.queue_name} queue...")
        self.queue.append(hive_message)

    def dequeue(self) -> Optional[HiveMessage]:
        """
        Removes and returns the first HiveMessage from the queue.

        Returns:
        -------
        Optional[HiveMessage]
            The first message in the queue, or None if the queue is empty.
        """
        if len(self.queue) > 0:
            self.logger.debug("MessageQueue", f"Removing message from {self.queue_name} queue...")
            return self.queue.pop(0)
        return None

    def list_messages(self) -> None:
        """
        Logs the messages currently in the queue.
        """
        self.logger.info("MessageQueue", "-" * AppSettings.LOG_LINE_WIDTH)
        self.logger.info("MessageQueue", f"{self.queue_name} message count: {len(self.queue)}")
        for message in self.queue:
            self.logger.info("MessageQueue", "-" * (AppSettings.LOG_LINE_WIDTH // 2))
            self.logger.info("MessageQueue", f"Sender: [{message.message.sender.friendly_name}|{message.message.sender.ip_address}|{message.message.sender.port_number}]")
            self.logger.info("MessageQueue", f"Recipient: [{message.message.recipient.friendly_name}|{message.message.recipient.ip_address}|{message.message.recipient.port_number}]")
            self.logger.info("MessageQueue", f"Message: {message.message.to_json()}")
            self.logger.info("MessageQueue", f"Send Attempt Count: {message.send_attempt_count}")
        self.logger.info("MessageQueue", "-" * AppSettings.LOG_LINE_WIDTH)
