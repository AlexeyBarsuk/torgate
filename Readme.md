# TORGATE
The utility to creates a set of tor proxy servers.

## Requirements
1. Linux, MacOS, not tested with Windows but possibly can work
2. Tor installed on your system
3. Python 3.7 +
4. Enough RAM
5. To run enough proxies you should edit your limits.conf and set nproc and nofile parameters

## Python requirements installation

```bash
pip3 install -r requirements.txt
```

## Usage
1. When you start the utility it takes it's defaults from config.py. So you can edit config.py as you need
````
python3 torgate.py
```
2. Also you can use command line arguments to do the same.
```
 python3 torgate.py --count 100 --tor_binary /opt/local/bin/tor --interface 127.0.0.1
```
To see all options use
```
 python3 torgate.py --help
```