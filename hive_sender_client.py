import socket
import time
from logger import Logger
from hive_message import HiveMessage
from message_queue import MessageQueue
from app_settings import AppSettings


class HiveSenderClient:
    """
    HiveSenderClient is responsible for sending messages from the outbound message queue to the appropriate recipient nodes.
    It continuously checks the outbound queue for messages, sends them over a TCP connection, and handles any connection errors.

    Attributes:
    ----------
    logger : Logger
        An instance of the Logger class for logging messages.
    outbound_message_queue : MessageQueue
        The queue for outbound messages.
    inbound_message_queue : MessageQueue
        The queue for inbound messages.
    """

    def __init__(self, outbound_message_queue: MessageQueue, inbound_message_queue: MessageQueue):
        """
        Initializes a new instance of HiveSenderClient.

        Parameters:
        ----------
        outbound_message_queue : MessageQueue
            The queue for outbound messages.
        inbound_message_queue : MessageQueue
            The queue for inbound messages.
        """
        self.logger: Logger = Logger()
        self.outbound_message_queue: MessageQueue = outbound_message_queue
        self.inbound_message_queue: MessageQueue = inbound_message_queue

        self.logger.debug("HiveSenderClient", "HiveSenderClient initialized...")

    def run(self) -> None:
        """
        Starts the client loop, which runs indefinitely.
        It continuously dequeues messages from the outbound message queue and sends them to the recipient nodes.
        """
        while True:
            message: HiveMessage = self.outbound_message_queue.dequeue()
            if message:
                self.send_message(message)
            time.sleep(AppSettings.QUEUE_SEND_SLEEP_IN_SECONDS)

    def send_message(self, hive_message: HiveMessage) -> None:
        """
        Sends a message to the recipient node over a TCP connection.

        Parameters:
        ----------
        hive_message : HiveMessage
            The message to be sent to the recipient node.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            try:
                client_socket.connect((hive_message.message.recipient.ip_address, int(hive_message.message.recipient.port_number)))
                self.logger.debug("HiveSenderClient", f"Connected to {hive_message.message.recipient.friendly_name}")
                client_socket.sendall(hive_message.message.to_json().encode())
                self.logger.debug("HiveSenderClient", f"Sent: {hive_message.message.to_json()}")
                data: bytes = client_socket.recv(1024)
                self.logger.debug("HiveSenderClient", f"Received: {data.decode()}")
            except ConnectionRefusedError:
                self.logger.error("HiveSenderClient", f"Connection to {hive_message.message.recipient.friendly_name} failed")
                hive_message.send_attempt_count += 1

                hive_message.message.recipient.increase_failed_connection_count()

                if hive_message.send_attempt_count >= AppSettings.MAX_SEND_ATTEMPTS:
                    self.logger.warning("HiveSenderClient", f"Failed to send message to {hive_message.message.recipient.friendly_name} after {AppSettings.MAX_SEND_ATTEMPTS} attempts")
                else:
                    self.outbound_message_queue.enqueue(hive_message)
            except AttributeError:
                self.logger.error("HiveSenderClient", f"Connection to {hive_message.message.recipient.friendly_name} at {hive_message.message.recipient.ip_address}:{hive_message.message.recipient.port_number} failed. Removing message from queue...")
