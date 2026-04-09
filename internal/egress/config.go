package egress

import (
	"fmt"
	"os"

	pb "prism/api/proto/control"

	"gopkg.in/yaml.v3"
)

type fileRoutingConfig struct {
	EgressNodes []fileEgressNode  `yaml:"egress_nodes"`
	Rules       []fileRoutingRule `yaml:"rules"`
}

type fileEgressNode struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
}

type fileRoutingRule struct {
	Match  fileRoutingMatch `yaml:"match"`
	Egress string           `yaml:"egress"`
}

type fileRoutingMatch struct {
	Domain  string         `yaml:"domain"`
	CIDR    []string       `yaml:"cidr"`
	GeoIP   fileGeoIPMatch `yaml:"geoip"`
	Default bool           `yaml:"default"`
}

type fileGeoIPMatch struct {
	Country []string `yaml:"country"`
}

// LoadRoutingFile reads a routing.yaml file and converts it into the control-plane proto form.
func LoadRoutingFile(path string) (*pb.RoutingConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read routing file: %w", err)
	}

	var cfg fileRoutingConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse routing file: %w", err)
	}

	out := &pb.RoutingConfig{
		Nodes: make([]*pb.EgressNodeProto, 0, len(cfg.EgressNodes)),
		Rules: make([]*pb.RoutingRuleProto, 0, len(cfg.Rules)),
	}

	for i, node := range cfg.EgressNodes {
		if node.Name == "" {
			return nil, fmt.Errorf("routing node %d: name required", i)
		}
		out.Nodes = append(out.Nodes, &pb.EgressNodeProto{
			Name:    node.Name,
			Address: node.Address,
		})
	}

	for i, rule := range cfg.Rules {
		if rule.Egress == "" {
			return nil, fmt.Errorf("routing rule %d: egress required", i)
		}

		matchCount := 0
		protoRule := &pb.RoutingRuleProto{
			EgressNode: rule.Egress,
		}

		if rule.Match.Domain != "" {
			matchCount++
			protoRule.Match = &pb.RoutingRuleProto_Domain{Domain: rule.Match.Domain}
		}
		if len(rule.Match.CIDR) > 0 {
			matchCount++
			protoRule.Match = &pb.RoutingRuleProto_Cidr{
				Cidr: &pb.CIDRMatch{Cidrs: append([]string(nil), rule.Match.CIDR...)},
			}
		}
		if len(rule.Match.GeoIP.Country) > 0 {
			matchCount++
			protoRule.Match = &pb.RoutingRuleProto_Geoip{
				Geoip: &pb.GeoIPMatch{Countries: append([]string(nil), rule.Match.GeoIP.Country...)},
			}
		}
		if rule.Match.Default {
			matchCount++
			protoRule.Match = &pb.RoutingRuleProto_IsDefault{IsDefault: true}
		}

		if matchCount != 1 {
			return nil, fmt.Errorf("routing rule %d: exactly one match clause is required", i)
		}

		out.Rules = append(out.Rules, protoRule)
	}

	return out, nil
}

// RulesFromProto converts a control-plane RoutingConfig into runtime router rules.
func RulesFromProto(cfg *pb.RoutingConfig) ([]Rule, error) {
	if cfg == nil {
		return nil, nil
	}

	nodes := make(map[string]*EgressNode, len(cfg.GetNodes()))
	for i, node := range cfg.GetNodes() {
		if node.GetName() == "" {
			return nil, fmt.Errorf("routing node %d: name required", i)
		}
		nodes[node.GetName()] = &EgressNode{
			Name:    node.GetName(),
			Address: node.GetAddress(),
		}
	}

	rules := make([]Rule, 0, len(cfg.GetRules()))
	for i, protoRule := range cfg.GetRules() {
		node, ok := nodes[protoRule.GetEgressNode()]
		if !ok {
			return nil, fmt.Errorf("routing rule %d: unknown egress node %q", i, protoRule.GetEgressNode())
		}

		rule := Rule{Node: node}
		switch match := protoRule.GetMatch().(type) {
		case *pb.RoutingRuleProto_Domain:
			if match.Domain == "" {
				return nil, fmt.Errorf("routing rule %d: domain match required", i)
			}
			rule.Type = RuleTypeDomain
			rule.Domain = match.Domain
		case *pb.RoutingRuleProto_Cidr:
			nets, err := ParseCIDRs(match.Cidr.GetCidrs())
			if err != nil {
				return nil, fmt.Errorf("routing rule %d: parse cidr: %w", i, err)
			}
			rule.Type = RuleTypeCIDR
			rule.CIDRNets = nets
		case *pb.RoutingRuleProto_Geoip:
			rule.Type = RuleTypeGeoIP
			rule.Countries = append([]string(nil), match.Geoip.GetCountries()...)
		case *pb.RoutingRuleProto_IsDefault:
			if !match.IsDefault {
				return nil, fmt.Errorf("routing rule %d: default match must be true", i)
			}
			rule.Type = RuleTypeDefault
		default:
			return nil, fmt.Errorf("routing rule %d: unsupported match", i)
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// HasRemoteNodes reports whether the config references at least one non-direct egress node.
func HasRemoteNodes(cfg *pb.RoutingConfig) bool {
	if cfg == nil {
		return false
	}
	for _, node := range cfg.GetNodes() {
		if node.GetAddress() != "" {
			return true
		}
	}
	return false
}
