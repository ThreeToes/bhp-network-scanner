# sniffer.py

## Running
This requires the `netaddr` module, which can be installed via 
`pip install -r requirements.txt`. You will require root access to be allowed
to bind to the required spot. 
Run `sudo python sniffer.py -o {HOST} -s {subnet}` on Linux/MacOS 

## Arguments
* `-h` Help
* `-o` or `-host` - the host IP to bind to
* `-s` or `-subnet` - the subnet to scan