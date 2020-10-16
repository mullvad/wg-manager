package portforward

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/digineo/go-ipset/v2"
	"github.com/mdlayher/netlink"
	"github.com/mullvad/wg-manager/api"
	"github.com/ti-mo/netfilter"
)

// Portforward is a utility for managing portforwarding
type Portforward struct {
	iptables  *iptables.IPTables
	ip6tables *iptables.IPTables
	chains    []Chain
	ipsetIPv4 string
	ipsetIPv6 string
}

// Chain contains a chain name and a transport protocol
type Chain struct {
	name              string
	transportProtocol string
}

// Iptables table to operate against
const table = "nat"

// Transport protocols that we want to create chains for
var transportProtocols = []string{"tcp", "udp"}

// New validates the addresses, ensures that the iptables portforwarding chains exists, and returns a new Portforward instance
func New(chainPrefix string, ipsetTableIPv4 string, ipsetTableIPv6 string) (*Portforward, error) {
	var chains []Chain
	for _, transportProtocol := range transportProtocols {
		chains = append(chains, Chain{
			name:              chainPrefix + "_" + strings.ToUpper(transportProtocol),
			transportProtocol: transportProtocol,
		})
	}

	ipt, err := newIPTables(chains, iptables.ProtocolIPv4)
	if err != nil {
		return nil, err
	}

	ip6t, err := newIPTables(chains, iptables.ProtocolIPv6)
	if err != nil {
		return nil, err
	}

	err = validateIPSet(ipsetTableIPv4)
	if err != nil {
		return nil, err
	}

	err = validateIPSet(ipsetTableIPv6)
	if err != nil {
		return nil, err
	}

	return &Portforward{
		iptables:  ipt,
		ip6tables: ip6t,
		chains:    chains,
		ipsetIPv4: ipsetTableIPv4,
		ipsetIPv6: ipsetTableIPv6,
	}, nil
}

func newIPTables(chains []Chain, protocol iptables.Protocol) (*iptables.IPTables, error) {
	ipt, err := iptables.NewWithProtocol(protocol)
	if err != nil {
		return nil, err
	}

	currentChains, err := ipt.ListChains("nat")
	if err != nil {
		return nil, err
	}

	for _, chain := range chains {
		if !chainExists(chain.name, currentChains, ipt) {
			return nil, fmt.Errorf("an iptables chain named %s does not exist", chain)
		}
	}

	return ipt, nil
}

func chainExists(chain string, currentChains []string, ipt *iptables.IPTables) bool {

	for _, currentChain := range currentChains {
		if currentChain == chain {
			return true
		}
	}

	return false
}

func validateIPSet(name string) error {
	conn, err := ipset.Dial(netfilter.ProtoUnspec, &netlink.Config{})
	if err != nil {
		return err
	}

	ipsets, err := conn.ListAll()

	for _, p := range ipsets {
		if p.Name.Get() == name {
			return nil
		}
	}

	return fmt.Errorf("an ipset named %s does not exist", name)
}

// UpdatePortforwarding updates the iptables rules for portforwarding to match the given list of peers
func (p *Portforward) UpdatePortforwarding(peers api.WireguardPeerList) {
	for _, chain := range p.chains {
		rules := make(map[string]iptables.Protocol)
		for _, peer := range peers {
			if len(peer.Ports) < 1 {
				continue
			}

			p.createPeerRules(peer, chain.transportProtocol, rules)
		}

		currentRules, err := p.getCurrentRules(chain.name)
		if err != nil {
			log.Printf("error getting current iptables rules %s", err.Error())
			return
		}

		// Add new portforwarding rules
		for rule, protocol := range rules {
			if _, ok := currentRules[rule]; !ok {
				ipt := p.iptables
				if protocol == iptables.ProtocolIPv6 {
					ipt = p.ip6tables
				}

				err := ipt.Append(table, chain.name, strings.Split(rule, " ")...)
				if err != nil {
					log.Printf("error adding iptables rule")
					continue
				}

			}
		}

		// Remove old portforwarding rules
		for rule, protocol := range currentRules {
			if _, ok := rules[rule]; !ok {
				ipt := p.iptables
				if protocol == iptables.ProtocolIPv6 {
					ipt = p.ip6tables
				}

				err := ipt.Delete(table, chain.name, strings.Split(rule, " ")...)
				if err != nil {
					log.Printf("error deleting iptables rule")
					continue
				}

			}
		}
	}
}

// AddPortforwarding tries to add portforwarding rules for a peer without checking existing ones
func (p *Portforward) AddPortforwarding(peer api.WireguardPeer) {
	if len(peer.Ports) < 1 {
		return
	}

	for _, chain := range p.chains {
		rules := make(map[string]iptables.Protocol)
		p.createPeerRules(peer, chain.transportProtocol, rules)

		// Add new portforwarding rules
		for rule, protocol := range rules {
			ipt := p.iptables
			if protocol == iptables.ProtocolIPv6 {
				ipt = p.ip6tables
			}

			err := ipt.Append(table, chain.name, strings.Split(rule, " ")...)
			if err != nil {
				log.Printf("error adding iptables rule")
				continue
			}
		}
	}

	return
}

// RemovePortforwarding tries to remove portforwarding rules for a peer without checking existing ones
func (p *Portforward) RemovePortforwarding(peer api.WireguardPeer) {
	if len(peer.Ports) < 1 {
		return
	}

	for _, chain := range p.chains {
		rules := make(map[string]iptables.Protocol)
		p.createPeerRules(peer, chain.transportProtocol, rules)

		// Remove old portforwarding rules
		for rule, protocol := range rules {
			ipt := p.iptables
			if protocol == iptables.ProtocolIPv6 {
				ipt = p.ip6tables
			}

			err := ipt.Delete(table, chain.name, strings.Split(rule, " ")...)
			if err != nil {
				log.Printf("error deleting iptables rule")
				continue
			}
		}
	}
}

func (p *Portforward) createPeerRules(peer api.WireguardPeer, transportProtocol string, rules map[string]iptables.Protocol) {
	// Ignore ip's with errors, in-case we get bad data from the API
	ipv4, _, err := net.ParseCIDR(peer.IPv4)
	if err != nil {
		return
	}

	rule := fmt.Sprintf("-p %s -m set --match-set %s dst -m multiport --dports %s -j DNAT --to-destination %s", transportProtocol, p.ipsetIPv4, getPortsString(peer.Ports), ipv4)
	rules[rule] = iptables.ProtocolIPv4

	ipv6, _, err := net.ParseCIDR(peer.IPv6)
	if err != nil {
		return
	}

	rule = fmt.Sprintf("-p %s -m set --match-set %s dst -m multiport --dports %s -j DNAT --to-destination %s", transportProtocol, p.ipsetIPv6, getPortsString(peer.Ports), ipv6)
	rules[rule] = iptables.ProtocolIPv6
}

func getPortsString(ports []int) string {
	sort.Ints(ports)

	slice := make([]string, len(ports))
	for i, v := range ports {
		slice[i] = strconv.Itoa(v)
	}

	return strings.Join(slice, ",")
}

func (p *Portforward) getCurrentRules(chain string) (map[string]iptables.Protocol, error) {
	rules := make(map[string]iptables.Protocol)

	ipv4Rules, err := p.iptables.List("nat", chain)
	if err != nil {
		return nil, err
	}

	ipv6Rules, err := p.ip6tables.List("nat", chain)
	if err != nil {
		return nil, err
	}

	for _, rule := range p.filterRules(chain, ipv4Rules) {
		rules[rule] = iptables.ProtocolIPv4
	}

	for _, rule := range p.filterRules(chain, ipv6Rules) {
		rules[rule] = iptables.ProtocolIPv6
	}

	return rules, nil
}

func (p *Portforward) filterRules(chain string, rules []string) []string {
	// Remove the first entry as it's the rule for creating the chain
	if len(rules) > 0 {
		rules = rules[1:]
	}

	var filteredRules []string
	for _, rule := range rules {
		// Remove the chain name
		rule = strings.TrimPrefix(rule, fmt.Sprintf("-A %s ", chain))
		// Remove the ip masks
		rule = strings.Replace(rule, "/32", "", -1)
		rule = strings.Replace(rule, "/128", "", -1)

		filteredRules = append(filteredRules, rule)
	}

	return filteredRules
}
