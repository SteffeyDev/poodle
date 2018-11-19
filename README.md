# POODLE
Working exploit code for the POODLE attack on SSLv3

### Setup

```
# sudo apt install python3 python3-pip build-essential python3-dev libnetfilter-queue-dev dsniff jq
# pip3 install NetfilterQueue scapy reprint
```

### Usage

Add proper values to `config.json` 
```
# sudo ./start_mitm
```

### How it works

#### Man in the Middle

The Man in the Middle (MitM) attack is conducted using ARP spoofing on a LAN, assuming that the attacker is on the same local area network as the target (client) computer.  The router is tricked into sending packets destined for the client to the attacker, and the client is tricked into sending packets destined for the router to the attacker.  The attacker, which is running `start_mitm`, will forward these packets to their correct destinations, so that the client and server are none the wiser.  This is done automatically if the values are set correctly in `config.json`.

#### POODLE Attack

Coming soon...
