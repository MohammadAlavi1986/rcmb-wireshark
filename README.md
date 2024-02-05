# Wireshark Dissector for RCmb (Redis Cluster message bus) Protocol

![RCmb Protocol Dissector Screenshot](screenshot.png?raw=true "RCmb Protocol Dissector Screenshot")

I wrote this simple dissector for the RCmb protocol to better understand the inner workings of Redis cluster described here: https://redis.io/docs/management/scaling/.<br> 
This dissector is registered for TCP ports 17000-17005. If you use different ports, change the following lines in the RCmb-dissector.lua file.
```
-- register rcmb protocol to handle tcp port 17000, 17001, 17002, 17003, 17004, 17005
udp_table:add(17000, rcmb_protocol)
udp_table:add(17001, rcmb_protocol)
udp_table:add(17002, rcmb_protocol)
udp_table:add(17003, rcmb_protocol)
udp_table:add(17004, rcmb_protocol)
udp_table:add(17005, rcmb_protocol)
```