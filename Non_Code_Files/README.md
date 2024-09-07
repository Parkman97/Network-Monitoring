# How to start the Application

## How to create the first node 

This command will be run in a command prompt to start the node:

Format:

python .\app_main.py -ip <IP address>> -port <port number> -friendly_name <Node name> -main <Boolean>

Example:

```python .\app_main.py -ip 127.0.0.1 -port 54321 -friendly_name LosAngeles -main True```

## How to start other nodes 

Format:

python .\app_main.py -ip <IP address>> -port <port number> -friendly_name <Node name>

Example:

```python .\app_main.py -ip 127.0.0.1 -port 54323 -friendly_name Brisbane```


## How to connect the nodes together

Run this command to connect to other nodes. It should be run the in the requestor nodes command line

connect <ip address> <port number>

Example that connects a node to LosAngeles node above:

```connect 127.0.0.1 54321```

## Command line interface

### Add Service
Format 
This command will add a new entry into the configuration. Parameters should be entered as read top to bottom in configuration.json 
```add <cityName> <ServiceName> <target> <parameters> <frequency>```

Example:
```add NeyYork DNS 192.168.26.35 mlbbaseball.com A 120 ```
### Edit Service
Allows for edits to be made to specific entries in the configuration dictionary. It will only make edits to the entries
that you specifically give it.

Format 
```edit <cityName> <ServiceName> <target> <dictKey=newValue>```

Example:
```edit NeyYork DNS 192.168.26.35 target=1.1.1.1 frequency=240 ```

### Delete Service
Deletes a service from the configuration 

Format 
```delete <cityName> <ServiceName> <target>```

Example:
```delete NeyYork DNS 192.168.26.35```

### Print Whole Hive configuration 
This command will print the entire configuration monitoring list to the terminal

```config_print```

### Print Local hive status for each monitoring service 
This command will print each monitoring check and its current status 

```status```