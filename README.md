# DDOS Guardian Layer 7 Version

## What is this?
DDoS Guardian Layer 7 Provides protection toward layer 7 website DDoS attacks.
The way it works is by adding a firewall that goes through DDoS Guardian that sends to the server, Which than checks if the request is friendly.

## Level 7 Setup

### Dependency
You will need DDoS Guardian to use this. Please [Install DDoS Guardian](https://github.com/xlelord9292/ddos-guardian "Install DDoS Guardian")

### Installing
You then go to the directory ``/etc/nginx/conf.d/ddos-guardian-layer-7`` and download **protection.lua** into it. Run this below to download it:
```sh
curl -Lo protection.lua https://raw.githubusercontent.com/DDOS-Guardian/DDoS-Guardian-Layer-7/main/protection.lua```

### Editing
After downloading everything, You need to edit a few things! First, there is a variable named "whitelist", You need to add your Server IP (Ex. 184.156.178.1). If you have a IPV4 and IPV6, Do this to allow your server to send all sorts of requests and ignore the firewalls between your server.
```lua
local whitelist = {
    "IP1",
	"IP2"
}```

Next, Please find this in the code, and change the "SITE-KEY_ to your Cloudflare Key.
```lua
<div class="g-recaptcha" data-sitekey="SITE-KEY" data-callback="onSubmit"></div> ```

## How to get the cloudflare key?
- 1. Go To Cloudflare

- 2. Go to Turnstile 

- 3. Press "Add Site"

- 4. Give it a name, Then click "Domains", "Managed", Then select "No" and press "Create". It will give you your Site Key!

## How do I link DDoS Guardian to Nginx?
There are a few ways you can do this! Look below to find out how.

#### Method 1: 
 You can edit the ``nginx.conf``, And add this below the ``http {``:
```lua
access_by_lua_file /etc/nginx/conf.d/ddos-guardian-layer-7/protection.lua;```

#### Method 2:
u can edit the files and add it below this line in ``nginx.conf``:
```lua
location / {```

# Support
If you need help trobleshooting, Please join the discord!
https://discord.gg/V9RucxEw82

# License
DDos-Guardian 2024©

This code is released under the [AGPL License](https://github.com/DDOS-Guardian/DDoS-Guardian-Layer-7/blob/main/license "AGPL License")

## Credits
Founder: Relational Throne
