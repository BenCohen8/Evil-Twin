## Evil-Twin
## What is EVIL TWIN?


Evil TWIN works is that the attacker connects to a network that is similar to the network that we know to make the user connect to it instead of the network.

 After the user connects to our network, we hear it and can extract from it information, passwords, personal details, and so on. </br>
![WIMIA-Gfx_01](https://github.com/BenCohen8/Evil-Twin/assets/74296478/7e52c155-cb6b-4860-a53d-6658a11de0db)

## How does the attack work?


The way in which we create the attack is in the language of Python in the library and the use of the 802.11 standard that actually regulates the communication in local networks. </br>
The attack on Evil TWIN is created so that AP shows the SSID (name network) in such a way that it sends Becoin. The user automatically attempts to connect to the ID that it had previously connected to. </br>
If for the network the user has defined to connect previously using the password if you have changed the ID for that network do not need to connect to the password at all.</br>
The user does not connect to the same AP, since it does not work the AP will not succeed in passing the process of validation before the user since he does not have the password. </br>
If the user was connected to the AP with a certain SSID but he collects a higher capacity than another IP with the same SSID, the user tries to connect to the new AP. </br>


## attack
1  Scan WLAN in the environment and view the various networks discovered. </br>
2 Make a fake AP Wifi network. </br>
3 Connecting users to the fake network. </br>
4 Creating a fake captive portal .</br>
5 Theft of information .</br>

## defense
1 take from the user the name of interface he is using.  </br>
2 See if there are two AP with the same MAK and SSID if there is one (EVIL TWIN ). </br>
3 If  the preceding paragraph happens, we would like to check if the evil twin AP sends us a lot of Deauthentication packets.</br>
4 If  the preceding paragraph happens, we want to remove the applicant from the user .</br>
5 Send a lot of Deauthentication packets to the attacker andthus protecting the user.</br>


