class AppSettings:
    """
    AppSettings holds the configuration settings for the Hive network application.

    Attributes:
    ----------
    DEFAULT_IP_ADDRESS : str
        The default IP address for the local node.
    DEFAULT_PORT_NUMBER : int
        The default port number for the local node.
    DEFAULT_FRIENDLY_NAME : str
        The default friendly name for the local node.
    GOSSIP_PROTOCOL_FREQUENCY_IN_SECONDS : int
        The frequency in seconds at which the gossip protocol runs.
    HEARTBEAT_PROTOCOL_FREQUENCY_IN_SECONDS : int
        The frequency in seconds at which the heartbeat protocol runs.
    QUEUE_SEND_SLEEP_IN_SECONDS : int
        The sleep duration in seconds between message send attempts.
    MAX_SEND_ATTEMPTS : int
        The maximum number of attempts to send a message.
    TIMESTAMP_FORMAT : str
        The format for timestamps in logs.
    LOG_LINE_WIDTH : int
        The width of log lines for formatting purposes.
    """

    DEFAULT_IP_ADDRESS: str = '127.0.0.1'
    DEFAULT_PORT_NUMBER: int = 54321
    DEFAULT_FRIENDLY_NAME: str = 'Local Node'
    DEFAULT_MAIN: str = 'No'

    GOSSIP_PROTOCOL_FREQUENCY_IN_SECONDS: int = 10
    HEARTBEAT_PROTOCOL_FREQUENCY_IN_SECONDS: int = 10
    QUEUE_SEND_SLEEP_IN_SECONDS: int = 5
    MAX_SEND_ATTEMPTS: int = 3

    TIMESTAMP_FORMAT: str = '%Y-%m-%d %H:%M:%S'
    LOG_LINE_WIDTH: int = 120
