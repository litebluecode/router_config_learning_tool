# router_config_learning_tool

## Introduction
This software is used for learning the network config of router wan interface, such as DHCP, static IP address info or PPPoE account info(username+password, not support PPPoE CHAP Auth type, only support PAP Auth type).

It's usefull to learn your own router network config when you forgot your network config, in especial PPPoE account info or the Static IP.

## How to build
build: run build.sh script
``` bash
./build.sh
```
clean build: remove the "build" directory
``` bash
rm -rf build/
```

## How to run
Just connect the Computer/Router with the target learning Router which you want to get network configs, like this: 
```
the Computer/Router which running the program "router_config_learning_tool" <== connected with network cable ==> the Wan interface of target Router
```

Run the program "router_config_learning_tool"(Maybe need root right), and power on the router(Make sure the router try to request IP or dial with PPPoE PAP Auth type).

when the times up, router network config will report to your console.
```bash
./router_config_learning_tool -Ieth0 -t120
```

## Example
"router_config_learning_tool" printed the "Report", PPPoE UserName is "028011122675", Passwd is "123456789A".
```
root@ubuntu:/home/ag/source/router_config_learning_tool# ./router_config_learning_tool -Iens33 -t150
router_config_learning_tool E pppoeLearnerInit-1728: listen on interface ens33
router_config_learning_tool E ipaddrLearnerInit-432: listen on interface ens33
router_config_learning_tool E learnerStopLearn-139: learned net PPPoE info!
router_config_learning_tool E learnerTimeoutHandler-155: -----------------------------
router_config_learning_tool E learnerTimeoutHandler-156: --- pid 28729: learn time(120) is up! ---
router_config_learning_tool E learnerTimeoutHandler-157: -----------------------------
router_config_learning_tool E applyProbeNetConfig-95: ------------------------- Report ---------------------------
router_config_learning_tool E applyProbeNetConfig-102: --- learn succeed: target net type is PPPoE, account (UserName=888011122675, Passwd=123456789A)
router_config_learning_tool E applyProbeNetConfig-172: ------------------------------------------------------------
router_config_learning_tool E learnerTimeoutHandler-170: router_config_learning_tool quit! (reason is learned-config, signal=14)
```

## Note
When this software is working, should not start the DHCP client/server or PPPoE client/server on the device which the software("router_config_learning_tool") is running. Otherwise, the network config of router wan interface will not be learned.

## License
The "router_config_learning_tool" should only be used for learn your own router network config. Please do not use for steal other people network config.

"router_config_learning_tool" is under the GPL license, it picked some "rp-pppoe" codes, such as PPPoE Discovery Stage and Event-driven mechanism.

rp-pppoe, a PPP-over-Ethernet redirector for pppd, based on GPL license.
Copyright (C) 2001-2012 Roaring Penguin Software Inc.
https://github.com/Distrotech/rp-pppoe

