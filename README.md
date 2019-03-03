# GG-HTTP
A Python man in the middle attacking tool  

![GG-HTTP](http://i67.tinypic.com/2i1dyc4.png)
### About
This tool sets up a MITM attack for you and sniffs HTTP requests.
It works on **OSX** and should also work on **Linux**.
There is no Windows support yet, and I'm not planning on implementing it soon.  

**GG-HHTP** features:
* Logs to a file (Your captured info is stored to a txt file).
* Sets up packet forwarding for you.
* Sniffs for HTTP requests and notices credentials.
* Automatically finds MAC addresses, you only need to input the target IP and gateway IP.  

### Usage
You can start the attack like this:
``` sudo python3 MITM.py -t <target IP> -g <gateway IP> -i interface ```
GG-HTTP also has a help option:
``` sudo python3 MITM.py -h ```
It is possible to use this tool together with SSLStrip to partially bypass HTTPS.
I've only managed to get it to work on Linux but most of the code is there so feel free make it working.

### Note
As you can see there are classes for setting up a webserver and replacing downloads.
The idea is to catch direct links to executables, so if the target downloads an executable we can send a response pointing to our webserver hosting a backdoor.
This way the user downloads our backdoor instead of the executable they are trying to download.
It is **not** fully working yet ands thats why it is not implemented yet. 
Once again feel free to contribute!

### Credits
GG-HTTP is inspired on work by Zaid Sabih.
Thanks for introducing me to Scapy!
