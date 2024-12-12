#include "rp.h"
#define TTE 16
#define TTL 16
#define IP_SIZE sizeof(IPAddress)
#include <cassert>

using namespace std;

void RPNode::send_segment(IPAddress dest_ip, std::vector<uint8_t> const& segment) const
{
    vector<uint8_t> packet(2 + 2 * IP_SIZE);
    packet[0] = 1; // signifies that the packet is an information packet
    packet[1] = TTL; // stores the TTL value of the packet
    memcpy(&packet[2],&ip,IP_SIZE);
    memcpy(&packet[6],&dest_ip,IP_SIZE);

    packet.insert(packet.end(), segment.begin(), segment.end());

    MACAddress dest_mac;
    if(ip_to_mac.count(dest_ip) > 0){
        dest_mac = ip_to_mac.at(dest_ip);
    }
    else{
        // log("The node isn't active yet, we will broacast to all neighbours hoping it becomes active at some point");
        broadcast_packet_to_all_neighbors(packet, true);
        return;
    }

    // Now, if the destination mac is found
    // We first check if the destination mac is present in the routing table
    if(routing_table.find(dest_mac) != routing_table.end()){
        // log(to_string(mac) +  " sending to " + to_string(dest_ip) + " through " + to_string(routing_table.at(dest_mac)->next_hop));
        send_packet(routing_table.at(dest_mac)->next_hop, packet, true);
    }
    else{
        // log("either the node hasnt been discovered or the node is DOWN, broadcast hoping someone will have it");
        broadcast_packet_to_all_neighbors(packet, true);
        return;
    }

}

void RPNode::receive_packet(MACAddress src_mac, std::vector<uint8_t> packet, size_t distance)
{
    if(packet[0] == 0){ // case where it is a routing table packet

        if(routing_table.find(src_mac) != routing_table.end()){
            routing_table.at(src_mac)->expiry_time = TTE; 
        }
        else{
            // we must create a new entry for this src_mac
            // if we have the ip in the table we can proceed normally
            if(ip_to_mac.find(src_mac) != ip_to_mac.end()){
                RoutingTableEntry* new_entry = create_entry(src_mac, ip_to_mac[src_mac], src_mac, distance, TTE); 
                routing_table[src_mac] = new_entry;
            }
            else{
                // log("Some issue, couldn't find src_mac's ip");
                RoutingTableEntry* new_entry = create_entry(src_mac, 0, src_mac, distance, TTE); 
                routing_table[src_mac] = new_entry;
            }
        }

        // now we go through the sender's routing table update our own as we do so
        for(size_t i = 1; i < packet.size(); i+=sizeof(RoutingTableEntry)){ //loop iteration skipping first index since that is the packet_type 
            RoutingTableEntry* entry = new RoutingTableEntry;
            memcpy(entry, &packet[i], sizeof(RoutingTableEntry));

            MACAddress entry_mac = entry->mac;
            IPAddress entry_ip = entry->ip;

            ip_to_mac[entry_ip] = entry_mac;
            mac_to_ip[entry_mac] = entry_ip;

            // we implement split horizon where we do not share the DV entry with a particular neighbour if that neighbour is the
            // next hop to the destination concerned. We do so while receiving, we just ignore the updates

            if(entry->next_hop == mac){
                delete entry;
                continue;
            }

            if(routing_table.find(entry_mac) == routing_table.end()){ 
                // this means that this mac address hasn't been discovered by our node yet
                // we must add it to our routing table
                RoutingTableEntry* new_entry = create_entry(entry_mac, entry_ip, src_mac, distance+entry->cost, entry->expiry_time);
                routing_table[entry_mac] = new_entry;
            }
            else{
                // if this node is reachable from our node through src_mac then we reset the Time to expiry
                // Because this means that the node must have been active for some reasonable period of time for it to remain active in src_mac
                
                if(src_mac == routing_table[entry_mac]->next_hop)
                    routing_table[entry_mac]->expiry_time = entry->expiry_time;

                // now we check if we have found a better path to this node 
                if(entry->cost + distance < routing_table[entry_mac]->cost){
                    routing_table[entry_mac]->next_hop = src_mac;
                    routing_table[entry_mac]->cost = entry->cost + distance;
                    routing_table[entry_mac]->expiry_time = entry->expiry_time;
                }

            }
            delete entry;
        }

        // update the entries in the routing table with the newly discovered ip addresses
        for(auto& entry : routing_table){
            if(entry.second->ip == 0 && mac_to_ip.find(entry.second->mac) != mac_to_ip.end()){
                entry.second->ip = mac_to_ip[entry.second->mac];
                // log("Updated ip address of "+to_string(entry.second->mac) + " to " + to_string(entry.second->ip) );
            }
        }
    }
    else{ // case where it is a segment packet

        IPAddress src_ip;
        IPAddress dest_ip;
        uint8_t ttl = packet[1]; // Extract TTL from packet

        memcpy(&src_ip, packet.data() + 2, sizeof(IPAddress));
        memcpy(&dest_ip, packet.data() + 6, sizeof(IPAddress));

        // if the packet is meant for us, extract the segment and report, otherwise we need to forward
        if (dest_ip == ip) {
            vector<uint8_t> segment(packet.begin() + 10, packet.end()); 
            receive_segment(src_ip, segment);
        }
        else{
            // We update the packet and check if TTL expired
            // we decrement the TTL
            ttl--;
            if(ttl == 0){ // we drop the packet
                // log("TTL expired, Packet Dropped!");
                return;
            }
            packet[1] = ttl; // update the ttl entry in the header

            // Check first whether the node ip is known
            MACAddress dest_mac;
            if(ip_to_mac.count(dest_ip) > 0){
                dest_mac = ip_to_mac.at(dest_ip);
            }
            else{
                // log("The node ip isn't known yet, we will broadcast to neighbours hoping someone knows it");
                broadcast_packet_to_all_neighbors(packet, true);
                return;
            }

            // Node is active, i.e. IP is known
            if(routing_table.find(dest_mac) == routing_table.end()){
                // ip is known but the routing table doesn't contain any information on the path to that node
                // Either path not found yet or expired, in either case we broadcast

                // log("Node is active but not in the routing table, we will broadcast");
                broadcast_packet_to_all_neighbors(packet, true);
            }
            else{
                // dest_mac found in routing table, we send it to that node
                // log("Sending packet from " + to_string(mac) + " to " + to_string(routing_table[dest_mac]->next_hop) + " for " + to_string(dest_mac));
                send_packet(routing_table[dest_mac]->next_hop, packet, true);
            }
        }
    }

}

void RPNode::do_periodic()
{   
    // add the ip - mac mapping of the node to the maps 
    mac_to_ip[mac] = ip;
    ip_to_mac[ip] = mac;

    if (routing_table.find(mac) == routing_table.end()) {
        RoutingTableEntry* new_entry = create_entry(mac, ip, mac, 0, TTE);
        routing_table[mac] = new_entry;
    }

    routing_table.find(mac)->second->expiry_time = TTE; // whenever we enter the node, we reset our own expiry time to the max 
    
    vector<MACAddress> deleted_macs;
    // for all the known mac addresses we decrement the TTE by 1 in each iteration and if the TTE reaches 0 we drop the node
    for (auto it = routing_table.begin(); it != routing_table.end(); ) {
        RoutingTableEntry* entry = it->second;

        entry->expiry_time--;

        if (entry->expiry_time == 0) {
            it = routing_table.erase(it);

            // you ensure that the node with next hop equal to that node is also deleted, so that a new path can be found
            deleted_macs.push_back(entry->mac);
        }
        else{
            ++it;
        }
    }

    for (auto mac : deleted_macs) {
        for (auto it = routing_table.begin(); it != routing_table.end(); ) {
            if (it->second->next_hop == mac) {
                it = routing_table.erase(it);  
            } else {
                ++it; 
            }
        }
    }


    // now create the packet to be broadcasted - note that for these we do not use TTL since we only do a single broadcast to all its neighbours
    vector<uint8_t> packet;
    packet.push_back(0); // signifies that the packet is a routing table broadcast packet

    for (auto& it : routing_table) {
        RoutingTableEntry* entry = it.second;  
        uint8_t* entry_bytes = reinterpret_cast<uint8_t*>(entry);  

        packet.insert(packet.end(), entry_bytes, entry_bytes + sizeof(RoutingTableEntry));
    }

    broadcast_packet_to_all_neighbors(packet, false);
}

// takes in m:mac address, i: ip address, nh: next_hop, c: cost and et: expiry_time
RPNode::RoutingTableEntry* RPNode::create_entry(MACAddress m, IPAddress i, MACAddress nh, int c, int et){
    RoutingTableEntry* new_entry = new RoutingTableEntry;
    new_entry->ip = i;
    new_entry->cost = c;
    new_entry->mac = m;
    new_entry->next_hop = nh;
    new_entry->expiry_time = et;
    return new_entry;
}