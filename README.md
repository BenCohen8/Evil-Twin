## Evil-Twin
## What is EVIL TWIN?
The way that Evil TWIN works is that the attacker sets up a fake wifi network that is similar to the network we know in order to make the user connect to it instead of a reliable network.</br>
After the user connects to our fake network,
we will listen to the traffic on his network and thus it is possible to extract password information and personal details...</br>

## How does the attack work?


The way we create the attack is in the python language in the Scapy library and using the 802.11 standard which is actually standards for wireless communication in local networks.
The attack in Evil TWIN is created so that the AP shows the SSID (network name) by sending Becoin.</br>
The user automatically tries to connect to an AP with an SSID that he was previously connected to.</br>
If for a certain network the user was previously configured to connect using a password, if we change the AP for that network, no password is required at all.</br>
The user does not connect to the same AP, since there is a two-sided identification process, it will not work, the AP will not be able to go through an authentication process with the user, since he does not have the password. If the user was connected to an AP with a certain SSID but he receives a higher power transmission from another IP with the same SSID, the user tries to connect to the new AP.
