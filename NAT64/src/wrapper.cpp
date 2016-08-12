/*
 *  WrapSix
 *  Copyright (C) 2008-2013  xHire <xhire@wrapsix.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <arpa/inet.h>		/* inet_pton */
#include <linux/ethtool.h>	/* struct ethtool_value */
#include <linux/if_ether.h>	/* ETH_P_ALL */
#include <linux/sockios.h>	/* SIOCETHTOOL */
#include <net/ethernet.h>	/* ETHERTYPE_* */
#include <net/if.h>		/* struct ifreq */
#include <netinet/in.h>		/* htons */
#include <netpacket/packet.h>	/* struct packet_mreq, struct sockaddr_ll */
#include <stdlib.h>	
#include <stdio.h>	/* srand */
#include <string.h>		/* strncpy */
#include <sys/ioctl.h>		/* ioctl, SIOCGIFINDEX */
#include <time.h>		/* time, time_t */
#include <unistd.h>		/* close */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include "arp.h"
#include "autoconfig.h"
#include "config.h"
#include "ethernet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "log.h"
#include "nat.h"
#include "transmitter.h"
#include "wrapper.h"
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <rte_config.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>

#include <string>
#include <iostream>

#include "caf/all.hpp"


using std::endl;
using std::string;
using std::cout;
using std::pair;
using namespace caf;

using start_atom = atom_constant<atom("start")>;






unsigned short mtu;
struct ifreq		interface;
struct s_mac_addr	mac;
struct s_ipv6_addr	ndp_multicast_addr;
struct s_ipv6_addr	wrapsix_ipv6_prefix;
struct s_ipv4_addr	wrapsix_ipv4_addr;
struct s_ipv6_addr	host_ipv6_addr;
struct s_ipv4_addr	host_ipv4_addr;




struct nat64_state{
	unsigned short mtu;
	struct ifreq*		interface_ptr;
	struct s_mac_addr*	mac_ptr;
	struct s_ipv6_addr*	ndp_multicast_addr_ptr;
	struct s_ipv6_addr*	wrapsix_ipv6_prefix_ptr;
	struct s_ipv4_addr*	wrapsix_ipv4_addr_ptr;
	struct s_ipv6_addr*	host_ipv6_addr_ptr;
	struct s_ipv4_addr*	host_ipv4_addr_ptr;
	radixtree_t *nat6_tcp, *nat6_udp, *nat6_icmp,
		    *nat4_tcp, *nat4_udp, *nat4_icmp,
		    *nat4_tcp_fragments;

	/* Linked lists for handling timeouts of connections */
	linkedlist_t *timeout_icmp, *timeout_udp,
		     *timeout_tcp_est, *timeout_tcp_trans,
		     *timeout_tcp_fragments;
};





int process(char *packet);


class nat64 : public event_based_actor{
public:
	nat64(actor_config& cfg):event_based_actor(cfg){

	}

    behavior make_behavior() override {
        //return firewall_fun(this);
     // send(this, step_atom::value);
    // philosophers start to think after receiving {think}
     // become(normal_task());
    //  become(keep_behavior, reconnecting());
    return behavior{

      [=](start_atom) {
         start();


      }

    };



}
    int start()
    {
    	struct s_cfg_opts	cfg;

    	struct packet_mreq	pmr;
    	struct ethtool_value	ethtool;

    	int	sniff_sock;
    	int	length;
    	char	buffer[PACKET_BUFFER];

    	int	i;
    	time_t	prevtime, curtime;

    	log_info(PACKAGE_STRING " is starting");

    	/* load configuration */

    	cfg_parse(SYSCONFDIR "/wrapsix.conf", &mtu, &cfg, 1);




    	log_info("Using: interface %s", cfg.interface);
    	log_info("       prefix %s", cfg.prefix);
    	log_info("       MTU %d", mtu);
    	log_info("       IPv4 address %s", cfg.ipv4_address);

    	/* get host IP addresses */
    	if (cfg_host_ips(cfg.interface, &host_ipv6_addr, &host_ipv4_addr,
    	    cfg.ipv4_address)) {
    		log_error("Unable to get host IP addresses");
    		return 1;
    	}
    	/* using block because of the temporary variable */
    	{
    		char ip_text[40];

    		inet_ntop(AF_INET, &host_ipv4_addr, ip_text, sizeof(ip_text));
    		log_info("       host IPv4 address %s", ip_text);
    		inet_ntop(AF_INET6, &host_ipv6_addr, ip_text, sizeof(ip_text));
    		log_info("       host IPv6 address %s", ip_text);
    	}
    	getchar();

    	/* initialize the socket for sniffing */
    /*	if ((sniff_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) ==
    	    -1) {
    		log_error("Unable to create listening socket");
    		return 1;
    	}

    	/* get the interface */
    /*	strncpy(interface.ifr_name, cfg.interface, IFNAMSIZ);
    	if (ioctl(sniff_sock, SIOCGIFINDEX, &interface) == -1) {
    		log_error("Unable to get the interface %s", cfg.interface);
    		return 1;
    	}

    	/* get interface's HW address (i.e. MAC) */
    /*	if (ioctl(sniff_sock, SIOCGIFHWADDR, &interface) == 0) {
    		memcpy(&mac, &interface.ifr_hwaddr.sa_data,
    		       sizeof(struct s_mac_addr));

    		/* disable generic segmentation offload */
    /*		ethtool.cmd = ETHTOOL_SGSO;
    		ethtool.data = 0;
    		interface.ifr_data = (caddr_t) &ethtool;
    		if (ioctl(sniff_sock, SIOCETHTOOL, &interface) == -1) {
    			log_error("Unable to disable generic segmentation "
    				  "offload on the interface");
    			return 1;
    		}

    		/* reinitialize the interface */
    /*		interface.ifr_data = NULL;
    		if (ioctl(sniff_sock, SIOCGIFINDEX, &interface) == -1) {
    			log_error("Unable to reinitialize the interface");
    			return 1;
    		}
    	} else {
    		log_error("Unable to get the interface's HW address");
    		return 1;
    	}

    	/* set the promiscuous mode */
    /*	memset(&pmr, 0x0, sizeof(pmr));
    	pmr.mr_ifindex = interface.ifr_ifindex;
    	pmr.mr_type = PACKET_MR_PROMISC;
    	if (setsockopt(sniff_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
    	    (char *) &pmr, sizeof(pmr)) == -1) {
    		log_error("Unable to set the promiscuous mode on the "
    			  "interface");
    		return 1;
    	}

    	/* some preparations */
    	/* compute binary IPv6 address of NDP multicast */
    	inet_pton(AF_INET6, "ff02::1:ff00:0", &ndp_multicast_addr);

    	/* compute binary IPv6 address of WrapSix prefix */
    	inet_pton(AF_INET6, cfg.prefix, &wrapsix_ipv6_prefix);

    	/* compute binary IPv4 address of WrapSix */
    	inet_pton(AF_INET, cfg.ipv4_address, &wrapsix_ipv4_addr);

    	/* initiate sending socket */
    	/*if (transmission_init()) {
    		log_error("Unable to initiate sending socket");
    		return 1;
    	}

    	/* initiate NAT tables */
    	nat_init();

    	/* initiate random numbers generator */
    	srand((unsigned int) time(NULL));

    	/* initialize time */
    	prevtime = time(NULL);

    	/* sniff! :c) */

    struct ether_header *m_pEthhdr;
    struct iphdr *m_pIphdr;
    char tmp1[2000];
    char *head=tmp1;
    char *packet=tmp1+34;
    uint16_t len;
    FILE* f;
      if( (f=fopen("code.txt","r"))==NULL)
    	  {
    	  printf("OPen File failure\n");
    	  }
    while (!feof(f))
       {
    	   fread(head,34,1,f);
    	   m_pEthhdr=(struct ether_header *)head;
    	   m_pIphdr=(struct iphdr *)(head+sizeof(struct ether_header));
    	   len = ntohs(m_pIphdr->tot_len);
    	   //cout<<"len:"<<len<<endl;
    	   fread(packet,len-20,1,f);
    	   process(head);
    	   getstate();

      }

    	/* clean-up */
    	/* close sending socket */
    //	transmission_quit();

    	/* empty NAT tables */
    	nat_quit();

    	/* unset the promiscuous mode */
    /*	if (setsockopt(sniff_sock, SOL_PACKET, PACKET_DROP_MEMBERSHIP,
    	    (char *) &pmr, sizeof(pmr)) == -1) {
    		log_error("Unable to unset the promiscuous mode on the "
    			  "interface");
    		/* do not call return here as we want to close the socket too */
    /*	}

    	/* close the socket */
    /*	close(sniff_sock); */

    	return 0;
    }

    /*
     	unsigned short mtu;
	struct ifreq*		interface_ptr;
	struct s_mac_addr*	mac_ptr;
	struct s_ipv6_addr*	ndp_multicast_addr_ptr;
	struct s_ipv6_addr*	wrapsix_ipv6_prefix_ptr;
	struct s_ipv4_addr*	wrapsix_ipv4_addr_ptr;
	struct s_ipv6_addr*	host_ipv6_addr_ptr;
	struct s_ipv4_addr*	host_ipv4_addr_ptr;
	radixtree_t *nat6_tcp, *nat6_udp, *nat6_icmp,
		    *nat4_tcp, *nat4_udp, *nat4_icmp,
		    *nat4_tcp_fragments;

	 Linked lists for handling timeouts of connections
	linkedlist_t *timeout_icmp, *timeout_udp,
		     *timeout_tcp_est, *timeout_tcp_trans,
		     *timeout_tcp_fragments;
     */



    void getstate(){
    	nat64_state_ptr->mtu=mtu;
    	nat64_state_ptr->interface_ptr=&interface;
    	nat64_state_ptr->mac_ptr=&mac;
    	nat64_state_ptr->ndp_multicast_addr_ptr=&ndp_multicast_addr;
    	nat64_state_ptr->wrapsix_ipv6_prefix_ptr=&wrapsix_ipv6_prefix;
    	nat64_state_ptr->wrapsix_ipv4_addr_ptr=&wrapsix_ipv4_addr;
    	nat64_state_ptr->host_ipv6_addr_ptr=&host_ipv6_addr;
    	nat64_state_ptr->host_ipv4_addr_ptr=&host_ipv4_addr;
    	nat64_state_ptr->nat6_tcp=nat6_tcp;
    	nat64_state_ptr->nat6_udp=nat6_udp;
    	nat64_state_ptr->nat6_icmp=nat6_icmp;
    	nat64_state_ptr->nat4_tcp=nat4_tcp;
    	nat64_state_ptr->nat4_udp=nat4_udp;
    	nat64_state_ptr->nat4_icmp=nat4_icmp;
    	nat64_state_ptr->nat4_tcp_fragments=nat4_tcp_fragments;
    	nat64_state_ptr->timeout_icmp=timeout_icmp;
    	nat64_state_ptr->timeout_udp=timeout_udp;
    	nat64_state_ptr->timeout_tcp_est=timeout_tcp_est;
    	nat64_state_ptr->timeout_tcp_trans=timeout_tcp_trans;
    	nat64_state_ptr->timeout_tcp_fragments=timeout_tcp_fragments;

    }



	struct nat64_state* nat64_state_ptr;
};


/**
 * Translator of IPv6 address with embedded IPv4 address to that IPv4 address.
 *
 * @param	ipv6_addr	IPv6 address (as data source)
 * @param	ipv4_addr	Where to put final IPv4 address
 */
void ipv6_to_ipv4(struct s_ipv6_addr *ipv6_addr, struct s_ipv4_addr *ipv4_addr)
{
	memcpy(ipv4_addr, ipv6_addr->addr + 12, 4);
}

/**
 * Translator of IPv4 address to IPv6 address with WrapSix' prefix.
 *
 * @param	ipv4_addr	IPv4 address (as data source)
 * @param	ipv6_addr	Where to put final IPv6 address
 */
void ipv4_to_ipv6(struct s_ipv4_addr *ipv4_addr, struct s_ipv6_addr *ipv6_addr)
{
	memcpy(ipv6_addr, &wrapsix_ipv6_prefix, 12);
	memcpy(ipv6_addr->addr + 12, ipv4_addr, 4);
}

void caf_main(actor_system& system) {
	int ret;
	unsigned lcore_id;
	char c[] = {"./build/bin/hellodpdk"};
	char* t = c;
	ret = rte_eal_init(1, &t);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");
	/* call lcore_hello() on every slave lcore */
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		rte_eal_remote_launch(lcore_hello, NULL, lcore_id);
	}

	/* call it on master lcore too */
	lcore_hello(NULL);

	rte_eal_mp_wait_lcore();

	// our CAF environment
  auto nat64_actor=system.spawn<nat64>();
  auon_send(nat64_actor,start_atom::value);
}

CAF_MAIN()


