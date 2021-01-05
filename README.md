# PyBeacon

PyBeacon is a collection of scripts for dealing with Cobalt Strike's encrypted traffic.

It can encrypt/decrypt beacon metadata, as well as parse symmetric encrypted taskings

# Scripts included

There is a small library which includes encryption/decoding methods, however some example scripts are included.

* stager-decode.py - this tool will simply decode a beacon DLL from a stager URL (you can use it to extract the public key).
* register.py - this tool deals with RSA encrypted metadata and can register a new (fake) beacon on a target Teamserver.
* tasktool.py - this tool deals with AES encrypted taskings to/from the teamserver. Use it to send callbacks to the teamserver, or for decoding taskings from a Teamserver to the beacon.
* ~~cs-3-5-rce.py - This is an implementation of the exploit used to exploit CS < 3.5-hf1, which was used in the wild to hack Cobalt Strike servers. It works by registering a beacon with a directory traversal in the IP address field. It then subsequently registers a download callback which causes the "download" to be uploaded anywhere on the target file system. The ITW exploit used a cronjob to achieve RCE.~~

# TODO

* Add more task types to the task decoding logic
* Add decoding for beacon taskings. At the moment some "generic" logic is used, but it's not really helpful
