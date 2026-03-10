package netctl

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

const (
	// IPRulePrefBase is the starting priority for macflow ip rules.
	IPRulePrefBase = 20000
	// MarkTableBase is the starting routing table number.
	MarkTableBase = 100
)

// ApplyIPRules configures ip rule + route for each managed device mark.
// mode: "whitelist"/"blacklist" → tun routing; "block" → blackhole
func ApplyIPRules(marks []int, mode string) (string, error) {
	// First, flush old macflow rules
	if err := flushIPRules(); err != nil {
		return "", fmt.Errorf("flush ip rules: %w", err)
	}

	if len(marks) == 0 {
		return "flushed", nil
	}

	sort.Ints(marks)

	var results []string
	for i, mark := range marks {
		pref := IPRulePrefBase + i
		table := MarkTableBase + i

		if mode == "block" {
			// Blackhole mode
			cmd := exec.Command("ip", "-4", "rule", "add",
				"pref", fmt.Sprintf("%d", pref),
				"fwmark", fmt.Sprintf("0x%x", mark),
				"blackhole")
			if out, err := cmd.CombinedOutput(); err != nil {
				results = append(results, fmt.Sprintf("rule blackhole 0x%x: error: %s", mark, string(out)))
			}
		} else {
			// Routing through tun
			cmd := exec.Command("ip", "-4", "rule", "add",
				"pref", fmt.Sprintf("%d", pref),
				"fwmark", fmt.Sprintf("0x%x", mark),
				"lookup", fmt.Sprintf("%d", table))
			if out, err := cmd.CombinedOutput(); err != nil {
				results = append(results, fmt.Sprintf("rule 0x%x: %s", mark, string(out)))
				continue
			}

			// Add default route via singtun0
			cmd = exec.Command("ip", "-4", "route", "replace",
				"table", fmt.Sprintf("%d", table),
				"default", "dev", "singtun0")
			if out, err := cmd.CombinedOutput(); err != nil {
				results = append(results, fmt.Sprintf("route 0x%x: %s", mark, string(out)))
			}
		}
	}

	if len(results) > 0 {
		return "partial: " + strings.Join(results, "; "), nil
	}
	return "applied", nil
}

// FlushIPRules removes all macflow ip rules (pref 20000-29999).
func FlushIPRules() error {
	return flushIPRules()
}

func flushIPRules() error {
	// List current rules and delete ones in our range
	out, err := exec.Command("ip", "-4", "rule", "show").CombinedOutput()
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Parse priority from "20001:	from all fwmark 0x100 lookup 100"
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		prefStr := strings.TrimSpace(line[:colonIdx])
		var pref int
		if _, err := fmt.Sscanf(prefStr, "%d", &pref); err != nil {
			continue
		}
		if pref >= IPRulePrefBase && pref < IPRulePrefBase+10000 {
			exec.Command("ip", "-4", "rule", "del", "pref", fmt.Sprintf("%d", pref)).Run()
		}
	}

	// Flush routing tables in our range
	for t := MarkTableBase; t < MarkTableBase+256; t++ {
		exec.Command("ip", "-4", "route", "flush", "table", fmt.Sprintf("%d", t)).Run()
	}

	return nil
}
