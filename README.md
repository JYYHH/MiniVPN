## 0. Prerequirement
- use [SEED Ubuntu12.04 VM (32-bit)](https://seedsecuritylabs.org/lab_env.html) as your program's environment.
- successfully installed `OpenSSL` (in the VM above it should be `OpenSSL 1.0.1`) in you VM's Linux system

## 1. Compile and Clean-up
- Compile: type `make`
- Clean-up: type `make clean`

### 1.1 Security Implementation
1. Confidential: OpenSSL AES-256 CBC Mode
2. Integrity: OpenSSL HMAC-SHA256 Hashing Function
3. Authenticity: Set-up a local CA (related files are kept locally and not uploaded onto GitHub)

## 2. Running Demo (Multiple VPN Tunnels)
### 2.1 Set up the tunnels
- Suppose you have 4 VMs running under the same local network(`192.168.15.0/24`), they are:
    1. "vm_0" (`192.168.15.4`)
    2. "jin511_" (`192.168.15.5`)
    3. "vm_3" (`192.168.15.7`)
    4. "vm_4" (`192.168.15.8`)
    - (Actually they are the real VMs which running on the Purdue Server `mc20` under my user's subnet `jin511`)
1. In `192.168.15.4:/<path_2_working_dir>`:
    - Type `sudo su`
    - Type `sudo ./simpletun -i tun0 -s -d` to start the server tun0 on `192.168.15.4` (virtual ip address `10.0.1.1`)
    - Then in another window (or you can make the script above running in the backgroung), type `bash first.sh` to configure tun0's virtual ip address and the local route table
2. In `192.168.15.5:/<path_2_working_dir>`:
    - Type `sudo su`
    - Type `sudo ./simpletun -i tun0 -c 192.168.15.4 -d -v 10.0.2.1` to start the client tun0 on `192.168.15.5` (virtual ip address `10.0.2.1`)
    - Then in another window (or you can make the script above running in the backgroung), type `bash second.sh` to configure tun0's virtual ip address and the local route table
3. In `192.168.15.7:/<path_2_working_dir>`:
    - Type `sudo su`
    - Type `sudo ./simpletun -i tun0 -c 192.168.15.4 -d -v 10.0.3.1` to start the client tun0 on `192.168.15.7` (virtual ip address `10.0.3.1`)
    - Then in another window (or you can make the script above running in the backgroung), type `bash third.sh` to configure tun0's virtual ip address and the local route table
4. In `192.168.15.8:/<path_2_working_dir>`:
    - Type `sudo su`
    - Type `sudo ./simpletun -i tun0 -c 192.168.15.4 -d -v 10.0.4.1` to start the client tun0 on `192.168.15.8` (virtual ip address `10.0.4.1`)
    - Then in another window (or you can make the script above running in the backgroung), type `bash forth.sh` to configure tun0's virtual ip address and the local route table

- __Note that you can enter `0\n` (change session key randomly) or `1\n` (change session iv (for encryption)) on the client side in the same terminal of `./simpletun ...`.__

### 2.2 Use the (bi-direction) tunnels
- Now, everything is done!
- You can manipulate any network operations between `10.0.1.1/24` and `10.0.2.1/24`/`10.0.3.1/24`/`10.0.4.1/24` (but not among last three)
- For example:
    - in "vm_0", type `ssh cs528user@10.0.2.1`/`ssh cs528user@10.0.3.1`/`ssh cs528user@10.0.4.1`
    - in "vm_3", type `ping 10.0.1.1`
    - in "jin511_", type `ssh cs528user@10.0.1.1`
    - ....
- __Note that, all the ssh/ping/<other_network_operations> can be run simultaneously, with a normal functionality__, since I already implemented a server which can build independent tunnels and multiple processes to handle requests from different addresses in parallel.



