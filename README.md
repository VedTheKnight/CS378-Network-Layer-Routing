I have implemented the Distance Vector Protocol.

The Key Data structures are Routing Table and IP to MAC mapping. 
The Routing Table maintained for each node stores the mapping from the MAC Address to the Routing Table Entry which contains : i. MAC Addr, ii. IP Addr, iii. Cost to get to the node, iv. Next Hop to get to the Node and v. Expiry Time of the entry.

Expiry Time is used to figure out when each node goes down. In each call of do periodic each node will decrement the expiry time by 1. If it becomes 0 we remove it from the table and remove all entries with next hop equal to that node - this is done so that a new shortest path can be found. 
We figure out which nodes are alive through the Routing Table Broadcasts (identified by 0 in their header bits). 
Whenever we receive a broadcast we first reset that senders expiry time. Then we see which nodes have next hop from our node to them equal to the broadcast sender. We set their expiry time to the expiry time according to the broadcast sender. In case we obtain a better path to that node, we update routing table and reset the TTE similarly. 
I have also implemented Split Horizon to deal with the count to infinity problem. Basically in the receive function, we check if the next hop for that entry is equal to our node, in which case we ignore that entry and move ahead through the routing table. 

We obtain the IP to MAC mapping from the broadcasts as well. Going through the Routing tables gives us the mappings eventually. 

We maintain TTL as usual, decrement it for each hop and finally if it becomes 0 we just drop the message. 

Format of segment messages is as follows : <1 byte : 1 denoting that info message> <1 byte : TTL> <source ip> <destination ip> <segments>
Format of broadcast messages is as follows : <1 byte : 0 denoting broadcast> <Routing Table Entries one by one>