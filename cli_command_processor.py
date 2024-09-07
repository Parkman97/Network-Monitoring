from logger import Logger
from hive_node import HiveNode
from hive_message import HiveMessage
from message_queue import MessageQueue
from config_message import ConfigMessage
from connect_message import ConnectMessage
from gossip_protocol_command_manager import GossipProtocolCommandManager
from heartbeat_protocol_command_manager import HeartbeatProtocolCommandManager
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from hive_node_manager import HiveNodeManager
from typing import Dict, Callable
from app_settings import AppSettings

import datetime
import json



class CliCommandProcessor:
    """
    CliCommandProcessor processes CLI commands for managing the Hive network.

    Attributes:
    ----------
    logger : Logger
        An instance of the Logger class for logging messages.
    prompt : str
        The CLI prompt string.
    commands_help : Dict[str, str]
        A dictionary mapping command names to their help descriptions.
    commands : Dict[str, Callable]
        A dictionary mapping command names to their corresponding methods.
    hive_node_manager : HiveNodeManager
        Manages the nodes in the Hive network.
    outbound_message_queue : MessageQueue
        A queue for outbound messages.
    inbound_message_queue : MessageQueue
        A queue for inbound messages.
    """

    def __init__(self, hive_node_manager: HiveNodeManager, outbound_message_queue: MessageQueue, inbound_message_queue: MessageQueue, appMain):
        """
        Initializes a new instance of CliCommandProcessor.

        Parameters:
        ----------
        hive_node_manager : HiveNodeManager
            Manages the nodes in the Hive network.
        outbound_message_queue : MessageQueue
            A queue for outbound messages.
        inbound_message_queue : MessageQueue
            A queue for inbound messages.
        """
        self.logger: Logger = Logger()

        self.prompt: str = "> "
        self.commands_help: Dict[str, str] = {
            "list_nodes": "Usage: list_nodes - List all nodes in the network",
            "list_outbound_messages": "Usage: list_outbound_messages - List all messages in the outbound message queue",
            "list_inbound_messages": "Usage: list_inbound_messages - List all messages in the inbound message queue",
            "connect": "Usage: connect <ip_address> <port> - Connect to a new node in the network",
            "enable_gossip_protocol": "Usage: enable_gossip_protocol - Enable the gossip protocol",
            "disable_gossip_protocol": "Usage: disable_gossip_protocol - Disable the gossip protocol",
            "enable_heartbeat_protocol": "Usage: enable_heartbeat_protocol - Enable the heartbeat protocol",
            "disable_heartbeat_protocol": "Usage: disable_heartbeat_protocol - Disable the heartbeat protocol",
            "exit": "Usage: exit - Shut down the node and exit application",
            "quit": "Usage: quit - Shut down the node and exit application",
            "help": "Usage: help - List all available commands",
            "config_print": "Shows the current configuration file",
            "add": "Add monitoring check. Format NTP/ICMP 'add cityName serviceName target interval', TCP/UDP/HTTP/HTTPS 'add cityName serviceName target port interval',DNS 'add cityName serviceName target domain type interval'",
            "edit": "Edit current monitoring check. Format 'edit cityName serviceName target <parameterName=newValue> Example 'edit London TCP 128.145.56.89 target=128.196.254.30 port=130' this updates two parameters",
            "delete": "Deletes monitoring check. Format 'delete cityName serviceName target",
            "status": "Prints the current status of the monitoring checks for the local city"
        }
        self.commands: Dict[str, Callable] = {
            "list_nodes": self.list_nodes,
            "list_outbound_messages": self.list_outbound_messages,
            "list_inbound_messages": self.list_inbound_messages,
            "connect": self.connect_to_node,
            "enable_gossip_protocol": self.enable_gossip_protocol,
            "disable_gossip_protocol": self.disable_gossip_protocol,
            "enable_heartbeat_protocol": self.enable_heartbeat_protocol,
            "disable_heartbeat_protocol": self.disable_heartbeat_protocol,
            "exit": self.process_command,
            "quit": self.process_command,
            "help": self.list_commands,
            "config_print": self.config_print,
            "add": self.add_service, 
            "edit": self.edit_service,
            "delete": self.delete_service,
            "status" : self.status,
        }
        self.hive_node_manager: HiveNodeManager = hive_node_manager
        self.outbound_message_queue: MessageQueue = outbound_message_queue
        self.inbound_message_queue: MessageQueue = inbound_message_queue
        self.app_main = appMain

        self.logger.debug("CliCommandProcessor", "CliCommandProcessor initialized...")

    def command_loop(self) -> None:
        """
        Starts the command loop, processing user input commands until "exit" or "quit" is received.
        """
        commands: list[str] = list(self.commands_help.keys())
        completer: WordCompleter = WordCompleter(commands, ignore_case=True)
        session: PromptSession = PromptSession(completer=completer)

        while True:
            try:
                with patch_stdout():
                    command: str = session.prompt(self.prompt)
                parts: list[str] = command.split()
                if not parts:
                    continue
                elif parts[0] in ["exit", "quit"]:
                    break
                elif parts[0] in ["help", "?"]:
                    self.list_commands()
                elif parts[0] == "list_nodes":
                    self.list_nodes()
                elif parts[0] == "list_outbound_messages":
                    self.list_outbound_messages()
                elif parts[0] == "list_inbound_messages":
                    self.list_inbound_messages()
                elif parts[0] == "enable_gossip_protocol":
                    self.enable_gossip_protocol()
                elif parts[0] == "disable_gossip_protocol":
                    self.disable_gossip_protocol()
                elif parts[0] == "enable_heartbeat_protocol":
                    self.enable_heartbeat_protocol()
                elif parts[0] == "disable_heartbeat_protocol":
                    self.disable_heartbeat_protocol()
                elif parts[0] == "connect":
                    if len(parts) < 3:
                        self.logger.info("CliCommandProcessor", self.commands_help["connect"])
                    else:
                        ip_address: str = parts[1]
                        port: str = parts[2]
                        self.connect_to_node(ip_address, port)
                elif parts[0] == "config_print":
                    self.config_print()
                elif parts[0] == "add":
                    self.add_service(parts)
                elif parts[0] == "edit":
                    self.edit_service(parts)
                elif parts[0] == "delete":
                    self.delete_service(parts)
                elif parts[0] == "status":
                    self.status()
                else:
                    self.logger.info("CliCommandProcessor", f"Unknown command: {command}")

            except (EOFError, KeyboardInterrupt):
                break

    def process_command(self, command: str) -> None:
        """
        Processes a given command by splitting it into its name and arguments, and executing the corresponding method.

        Parameters:
        ----------
        command : str
            The command string to process.
        """
        parts: list[str] = command.split()
        if not parts:
            return
        command_name: str = parts[0]
        command_args: list[str] = parts[1:]
        if command_name in self.commands:
            self.commands[command_name](*command_args)
        else:
            self.logger.info("CliCommandProcessor", f"Unknown command: {command}")

    def list_commands(self) -> None:
        """
        Lists all available commands with their descriptions.
        """
        self.logger.info("CliCommandProcessor", "Available commands:")
        for command, description in self.commands_help.items():
            self.logger.info("CliCommandProcessor", f"{command:<15} - {description}")

    def set_prompt(self, prompt: str) -> None:
        """
        Sets the CLI prompt string.

        Parameters:
        ----------
        prompt : str
            The new prompt string.
        """
        self.prompt = prompt

    def set_node_manager(self, hive_node_manager: HiveNodeManager) -> None:
        """
        Sets the HiveNodeManager instance.

        Parameters:
        ----------
        hive_node_manager : HiveNodeManager
            The HiveNodeManager instance to set.
        """
        self.hive_node_manager = hive_node_manager

    def list_nodes(self) -> None:
        """
        Lists all nodes in the network by calling the HiveNodeManager"s list_nodes method.
        """
        self.hive_node_manager.list_nodes()

    def list_outbound_messages(self) -> None:
        """
        Lists all messages in the outbound message queue by calling its list_messages method.
        """
        self.outbound_message_queue.list_messages()

    def list_inbound_messages(self) -> None:
        """
        Lists all messages in the inbound message queue by calling its list_messages method.
        """
        self.inbound_message_queue.list_messages()

    def connect_to_node(self, ip_address: str, port: str) -> None:
        """
        Connects to a new node in the network by creating a ConnectMessage and enqueueing it.

        Parameters:
        ----------
        ip_address : str
            The IP address of the node to connect to.
        port : str
            The port number of the node to connect to.
        """
        remote_node: HiveNode = HiveNode("remote_node", ip_address, int(port))
        connect_message: ConnectMessage = ConnectMessage(
            sender=self.hive_node_manager.local_node,
            recipient=remote_node,
            message="Hello"
        )
        new_hive_message: HiveMessage = HiveMessage(connect_message)
        self.outbound_message_queue.enqueue(new_hive_message)

    def enable_gossip_protocol(self) -> None:
        """
        Enables the gossip protocol by setting the appropriate flag in the GossipProtocolCommandManager.
        """
        GossipProtocolCommandManager.enable = True

    def disable_gossip_protocol(self) -> None:
        """
        Disables the gossip protocol by setting the appropriate flag in the GossipProtocolCommandManager.
        """
        GossipProtocolCommandManager.enable = False

    def enable_heartbeat_protocol(self) -> None:
        """
        Enables the heartbeat protocol by setting the appropriate flag in the HeartbeatProtocolCommandManager.
        """
        HeartbeatProtocolCommandManager.enable = True

    def disable_heartbeat_protocol(self) -> None:
        """
        Disables the heartbeat protocol by setting the appropriate flag in the HeartbeatProtocolCommandManager.
        """
        HeartbeatProtocolCommandManager.enable = False
    
    def config_print(self):
        """Prints configuration"""
        print("Node     | Service   | Parameters")
        print("--------------------------------------------------------------------------------------------------------------------")
        for hive_member in self.app_main.configuration_dict["config"]["Services"]:
            for key in self.app_main.configuration_dict["config"]["Services"][hive_member]:
                print(f"{hive_member}     | {key}     | {self.app_main.configuration_dict["config"]["Services"][hive_member][key]}")

    def add_service(self, parts):
        """add cityName ServiceName Target port interval"""
        try:
            config = self.app_main.configuration_dict
            city = parts[1]
            service_type = parts[2].upper()
            service_entry = {"target": parts[3].upper()}
            
            if service_type in ["HTTP", "HTTPS", "TCP", "UDP"]:
                service_entry["port"] = int(parts[4])
                service_entry["interval"] = int(parts[5])
            elif service_type == "DNS":
                service_entry["queries"] = {}
                service_entry["queries"]["domain"] = parts[4].lower()
                service_entry["queries"]["type"] = parts[5].lower()
                service_entry["interval"] = int(parts[6])

            elif service_type in ["NTP", "ICMP"]:
                service_entry["interval"] = int(parts[4])

            # Update Entry and version
            timestamp = datetime.datetime.now().strftime(AppSettings.TIMESTAMP_FORMAT)
            config["config"]["Services"][city][service_type] = service_entry
            config["config"]["version"] += 1
            config["config"]["datetime"] = timestamp

            #Send updated config to other nodes
            self.send_updated_config(config)
        except Exception as e:
             self.logger.info("CliCommandProcessor", f"Error due to {e}")

    def edit_service(self, parts):
        """edit cityName ServiceName Target editParts"""
        edit_dict = {}
        try:
            # Finds out which elements are to be edited
            for index, edit in enumerate(parts):
                if '=' in edit:
                    split_edits = parts[index].split('=')
                    edit_dict[split_edits[0].lower()] = split_edits[1].lower()

            if edit_dict:
                config = self.app_main.configuration_dict
                city = parts[1]
            
                service_type = parts[2].upper()
            
                target = parts[3]

                config_current = config['config']['Services'][city]

                for service in config_current:
                    if config_current[service]['target'] == target:
                
                    
                        for edits, value in edit_dict.items():
                            if edits in ["domain", "type"]:
                                del config_current[service_type]["queries"][edits]
                                config_current[service_type]["queries"][edits] = value
                           
                            else:
                                del config_current[service_type][edits]
                                config_current[service_type][edits] = value
                        
            
                #Updates entry in configurations
                self.logger.info("CliCommandProcessor", f"Edited config {config}")

                #Send updated config to other nodes
                self.send_updated_config(config)

            else:
                self.logger.info("CliCommandProcessor", "No edits entered")
                
        except Exception as e:
            self.logger.info("CliCommandProcessor", f"Error due to {e}")

    def delete_service(self, parts):
        """delete cityName ServiceName Target"""
        city = parts[1]
        service = parts[2].upper()
        target = parts[3]
        config = self.app_main.configuration_dict
        try:
            if config["config"]["Services"][city][service]["target"] == target:
                del config["config"]["Services"][city][service]
            else:
                self.logger.info("CliCommandProcessor", f"No such entry exist for {city}")
        except Exception as e:
            self.logger.info("CliCommandProcessor", f"Error invalid input{e}")

        # Sends updated configuration to other hive nodes
        self.send_updated_config(config)

    def send_updated_config(self, config: Dict):
        """Sends updated configuration to all current lives nodes"""

        # Update Entry and version
        timestamp = datetime.datetime.now().strftime(AppSettings.TIMESTAMP_FORMAT)
        config["config"]["version"] += 1
        config["config"]["datetime"] = timestamp

        updated_configuration = json.dumps(config)
        updated_configuration = updated_configuration.replace("'", '"')

        for random_node in self.hive_node_manager.get_all_live_nodes():
            if random_node.friendly_name != self.app_main.name:
                Config_message: ConfigMessage = ConfigMessage(
                            sender=self.hive_node_manager.local_node,
                            recipient=random_node,
                            message=updated_configuration,
                            )
                new_hive_message: HiveMessage = HiveMessage(Config_message)
                self.outbound_message_queue.enqueue(new_hive_message)

                # edit NewYork NTP time3.google.com  target=time5.google.com interval=60
    
    def status(self):
        """Prints configuration"""
        print("Node     | Service   | Current Status")
        print("--------------------------------------------------------------------------------------------------------------------")
        for service in self.app_main.results_dict[self.app_main.name]:
                print(f"{self.app_main.name}     | {service}     | {self.app_main.results_dict[self.app_main.name][service]}")