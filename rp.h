#ifndef RP_H
#define RP_H

#include "../node.h"

#include <bits/stdc++.h>
#include <vector>

class RPNode : public Node {

public:

    class RoutingTableEntry {
    public:
        MACAddress mac;
        IPAddress ip;
        MACAddress next_hop;
        size_t cost;
        int expiry_time;
    };

    std::map<MACAddress, RoutingTableEntry*> routing_table;
    std::map<MACAddress, IPAddress> mac_to_ip;
    std::map<IPAddress, MACAddress> ip_to_mac;
    RoutingTableEntry* create_entry(MACAddress m, IPAddress i, MACAddress nh, int c, int et);


    /*
     * NOTE You may not modify the constructor of this class
     */
    RPNode(Simulation* simul, MACAddress mac, IPAddress ip) : Node(simul, mac, ip) { }

    void send_segment(IPAddress dest_ip, std::vector<uint8_t> const& segment) const override;
    void receive_packet(MACAddress src_mac, std::vector<uint8_t> packet, size_t distance) override;
    void do_periodic() override;
};

#endif
