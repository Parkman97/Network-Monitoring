import datetime
import threading
from typing import Optional
from app_settings import AppSettings


class Logger:
    """
    Logger is a singleton class responsible for logging messages with different log levels to the console and optionally to a file.

    Attributes:
    ----------
    LogLevel : class
        A nested class defining different log levels: DEBUG, INFO, WARNING, ERROR.
    default_log_level : int
        The default log level for the logger.
    class_list : dict
        A dictionary mapping class names to their respective log levels.
    log_file : Optional[str]
        The file path for the log file, if set.
    max_source_width : int
        The maximum width of the source name for formatting purposes.
    """

    class LogLevel:
        DEBUG = 0
        INFO = 1
        WARNING = 2
        ERROR = 3

    default_log_level = LogLevel.INFO

    class_list = {
        "HiveNode": LogLevel.INFO,
        "HiveNodeManager": LogLevel.INFO,
        "HiveReceiverService": LogLevel.INFO,
        "HiveSenderClient": LogLevel.INFO,
        "CliCommandProcessor": LogLevel.INFO,
        "InboundQueueCommandProcessor": LogLevel.INFO,
        "GossipProtocolCommandManager": LogLevel.INFO,
        "HeartbeatProtocolCommandManager": LogLevel.INFO,
        "AppMain": LogLevel.INFO,
    }

    _instance: Optional['Logger'] = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> 'Logger':
        """
        Ensures that only one instance of Logger is created (Singleton pattern).

        Returns:
        -------
        Logger
            The singleton instance of Logger.
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(Logger, cls).__new__(cls)
                    cls._instance._initialize()
        return cls._instance

    def _initialize(self) -> None:
        """
        Initializes the Logger instance by setting the log file to None and calculating the max source width.
        """
        self.log_file: Optional[str] = None
        self.max_source_width: int = max(len(source) for source in self.class_list)

    def set_log_file(self, file_path: str) -> None:
        """
        Sets the log file path for logging messages to a file.

        Parameters:
        ----------
        file_path : str
            The path to the log file.
        """
        self.log_file = file_path

    def set_log_level(self, class_name: str, log_level: int) -> None:
        """
        Sets the log level for a specific class.

        Parameters:
        ----------
        class_name : str
            The name of the class for which the log level is to be set.
        log_level : int
            The log level to set.
        """
        self.class_list[class_name] = log_level
        self.max_source_width = max(self.max_source_width, len(class_name))

    def log(self, message_source: str, message_log_level: int, message: str) -> None:
        """
        Logs a message if the message log level is less than or equal to the class log level.

        Parameters:
        ----------
        message_source : str
            The source of the message (usually the class name).
        message_log_level : int
            The log level of the message.
        message : str
            The message to be logged.
        """
        if self.class_list.get(message_source, self.default_log_level) <= message_log_level:
            timestamp = datetime.datetime.now().strftime(AppSettings.TIMESTAMP_FORMAT)
            log_message = f"[{timestamp}][{message_source:<{self.max_source_width}}][{self._log_level_name(message_log_level):7}] {message}"
            print(log_message)
            if self.log_file:
                with open(self.log_file, 'a') as file:
                    file.write(f"{log_message}\n")

    @staticmethod
    def _log_level_name(log_level: int) -> str:
        """
        Returns the name of the log level.

        Parameters:
        ----------
        log_level : int
            The log level.

        Returns:
        -------
        str
            The name of the log level.
        """
        if log_level == Logger.LogLevel.DEBUG:
            return "DEBUG"
        elif log_level == Logger.LogLevel.INFO:
            return "INFO"
        elif log_level == Logger.LogLevel.WARNING:
            return "WARNING"
        elif log_level == Logger.LogLevel.ERROR:
            return "ERROR"
        return "UNKNOWN"

    def debug(self, message_source: str, message: str) -> None:
        """
        Logs a debug message.

        Parameters:
        ----------
        message_source : str
            The source of the message (usually the class name).
        message : str
            The message to be logged.
        """
        self.log(message_source, self.LogLevel.DEBUG, message)

    def info(self, message_source: str, message: str) -> None:
        """
        Logs an info message.

        Parameters:
        ----------
        message_source : str
            The source of the message (usually the class name).
        message : str
            The message to be logged.
        """
        self.log(message_source, self.LogLevel.INFO, message)

    def warning(self, message_source: str, message: str) -> None:
        """
        Logs a warning message.

        Parameters:
        ----------
        message_source : str
            The source of the message (usually the class name).
        message : str
            The message to be logged.
        """
        self.log(message_source, self.LogLevel.WARNING, message)

    def error(self, message_source: str, message: str) -> None:
        """
        Logs an error message.

        Parameters:
        ----------
        message_source : str
            The source of the message (usually the class name).
        message : str
            The message to be logged.
        """
        self.log(message_source, self.LogLevel.ERROR, message)
