import datetime
from typing import Dict, Optional
from app_settings import AppSettings


class HiveNode:
    """
    HiveNode represents a node in the network. Each node has a friendly name, IP address, port number,
    and various status attributes to track its state and health.

    Attributes:
    ----------
    friendly_name : str
        The friendly name of the node.
    ip_address : str
        The IP address of the node.
    port_number : int
        The port number on which the node is listening.
    last_heartbeat_timestamp : Optional[datetime.datetime]
        The timestamp of the last received heartbeat from this node.
    status : str
        The status of the node, either 'Live' or 'Dead'.
    failed_connection_count : int
        The number of consecutive failed connection attempts to this node.
    is_local_node : bool
        Indicates whether this node is the local node.
    """

    headers = {
        'friendly_name': 'Friendly Name',
        'ip_address': 'IP Address',
        'port': 'Port',
        'status': 'Status',  # 'Live', 'Dead'
        'last_heartbeat': 'Last Heartbeat',
        'failed_connections': 'Failed Connections',
    }

    def __init__(self, friendly_name: str, ip_address: str, port_number: int, is_local_node: bool = False):
        """
        Initializes a new instance of HiveNode.

        Parameters:
        ----------
        friendly_name : str
            The friendly name of the node.
        ip_address : str
            The IP address of the node.
        port_number : int
            The port number on which the node is listening.
        is_local_node : bool, optional
            Indicates whether this node is the local node (default is False).
        """
        self.friendly_name: str = friendly_name
        self.ip_address: str = ip_address
        self.port_number: int = port_number
        self.last_heartbeat_timestamp: Optional[datetime.datetime] = None
        self.status: str = "Live"
        self.failed_connection_count: int = 0
        self.is_local_node: bool = is_local_node

    def set_last_heartbeat_timestamp(self) -> None:
        """
        Sets the last heartbeat timestamp to the current time and resets the failed connection count.
        """
        self.last_heartbeat_timestamp = datetime.datetime.now()
        self.failed_connection_count = 0
        self.node_is_alive()

    def node_is_dead(self) -> None:
        """
        Sets the node status to 'Dead'.
        """
        self.status = "Dead"

    def node_is_alive(self) -> None:
        """
        Sets the node status to 'Live'.
        """
        self.status = "Live"

    def increase_failed_connection_count(self) -> None:
        """
        Increases the failed connection count by one. If the failed connection count exceeds the maximum
        allowed attempts, sets the node status to 'Dead'.
        """
        self.failed_connection_count += 1
        if self.failed_connection_count >= AppSettings.MAX_SEND_ATTEMPTS:
            self.node_is_dead()

    def get_node_list_row_header_as_str(self, col_widths: Dict[str, int]) -> str:
        """
        Returns a formatted string of the node list header, using the provided column widths.

        Parameters:
        ----------
        col_widths : Dict[str, int]
            A dictionary mapping column names to their respective widths.

        Returns:
        -------
        str
            A formatted string of the node list header.
        """
        return (f"{HiveNode.headers['friendly_name']:<{col_widths['friendly_name']}}"
                f" | {HiveNode.headers['ip_address']:<{col_widths['ip_address']}}"
                f" | {HiveNode.headers['port']:<{col_widths['port']}}"
                f" | {HiveNode.headers['status']:<{col_widths['status']}}"
                f" | {HiveNode.headers['last_heartbeat']:<{col_widths['last_heartbeat']}}"
                f" | {HiveNode.headers['failed_connections']:<{col_widths['Failed Connections']}}")

    def get_node_list_row_as_str(self, col_widths: Dict[str, int]) -> str:
        """
        Returns a formatted string representing the node's details, using the provided column widths.

        Parameters:
        ----------
        col_widths : Dict[str, int]
            A dictionary mapping column names to their respective widths.

        Returns:
        -------
        str
            A formatted string representing the node's details.
        """
        last_heartbeat: str = (self.last_heartbeat_timestamp.strftime(AppSettings.TIMESTAMP_FORMAT)
                               if self.last_heartbeat_timestamp else 'None')
        updated_friendly_name = self.friendly_name + '*' if self.is_local_node else self.friendly_name

        return (f"{updated_friendly_name:<{col_widths['friendly_name']}}"
                f" | {self.ip_address:<{col_widths['ip_address']}}"
                f" | {self.port_number:<{col_widths['port']}}"
                f" | {self.status:<{col_widths['status']}}"
                f" | {last_heartbeat:<{col_widths['last_heartbeat']}}"
                f" | {self.failed_connection_count:<{col_widths['Failed Connections']}}")

    def get_node_list_row_separator_as_str(self, col_widths: Dict[str, int]) -> str:
        """
        Returns a formatted string representing a separator line for the node list, using the provided column widths.

        Parameters:
        ----------
        col_widths : Dict[str, int]
            A dictionary mapping column names to their respective widths.

        Returns:
        -------
        str
            A formatted string representing a separator line for the node list.
        """
        return (f"{'-' * col_widths['friendly_name']}"
                f" | {'-' * col_widths['ip_address']}"
                f" | {'-' * col_widths['port']}"
                f" | {'-' * col_widths['status']}"
                f" | {'-' * col_widths['last_heartbeat']}"
                f" | {'-' * col_widths['Failed Connections']}")

    def __eq__(self, other: object) -> bool:
        """
        Checks if two HiveNode instances are equal based on their IP address and port number.

        Parameters:
        ----------
        other : object
            The other object to compare with.

        Returns:
        -------
        bool
            True if both instances have the same IP address and port number, False otherwise.
        """
        if isinstance(other, HiveNode):
            return self.ip_address == other.ip_address and self.port_number == other.port_number
        return False
