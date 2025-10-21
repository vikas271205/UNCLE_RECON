package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// Global Wappalyzer client
var wappalyzerClient *wappalyzer.Wappalyze

// Regular expression to find the title tag in HTML
var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)<\/title>`)

// Result struct
type ScanResult struct {
	URL           string
	StatusCode    int
	ContentLength int
	Title         string
	IPAddress     string
	Technologies  []string
}

func main() {
	target := flag.String("u", "", "Target domain (e.g., example.com)")
	outputFile := flag.String("o", "", "File to save output")
	concurrency := flag.Int("c", 50, "Concurrent tasks")
	matchCodesStr := flag.String("mc", "", "Match status codes, comma-separated")
	flag.Parse()

	if *target == "" {
		log.Fatal("[-] Target required. Use -u flag.")
	}

	var err error
	wappalyzerClient, err = wappalyzer.New()
	if err != nil {
		log.Fatalf("[-] Failed to init Wappalyzer: %v", err)
	}

	fmt.Printf("[*] Discovering subdomains for %s...\n", *target)
	subdomains := findSubdomains(*target)
	if len(subdomains) == 0 {
		log.Fatal("[-] No subdomains found.")
	}
	fmt.Printf("[+] Found %d subdomains.\n", len(subdomains))
	fmt.Println("[*] Probing for live hosts...")

	var wg sync.WaitGroup
	subdomainChan := make(chan string, *concurrency)
	resultsChan := make(chan ScanResult, *concurrency)

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go worker(subdomainChan, resultsChan, &wg)
	}

	go func() {
		for sub := range subdomains {
			subdomainChan <- sub
		}
		close(subdomainChan)
	}()

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var liveHosts []ScanResult
	for result := range resultsChan {
		liveHosts = append(liveHosts, result)
	}

	var filteredHosts []ScanResult
	if *matchCodesStr != "" {
		codes := parseMatchCodes(*matchCodesStr)
		for _, host := range liveHosts {
			if _, exists := codes[host.StatusCode]; exists {
				filteredHosts = append(filteredHosts, host)
			}
		}
	} else {
		filteredHosts = liveHosts
	}

	fmt.Printf("[+] Found %d live hosts matching criteria.\n", len(filteredHosts))
	saveOutput(filteredHosts, *outputFile)
}

func worker(subdomainChan <-chan string, resultsChan chan<- ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for subdomain := range subdomainChan {
		for _, scheme := range []string{"https", "http"} {
			url := fmt.Sprintf("%s://%s", scheme, subdomain)
			if result, ok := analyzeHost(url); ok {
				resultsChan <- *result
				break
			}
		}
	}
}

func findSubdomains(domain string) map[string]struct{} {
	subdomains := make(map[string]struct{})
	subdomains[domain] = struct{}{}

	client := &http.Client{Timeout: 20 * time.Second}
	req, _ := http.NewRequest("GET", fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain), nil)
	req.Header.Set("User-Agent", "UNCLE_RECON/1.0")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[!] Error fetching from crt.sh: %s\n", err)
		return subdomains
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[!] crt.sh returned non-200: %d\n", resp.StatusCode)
		return subdomains
	}

	type CrtShEntry struct {
		NameValue string `json:"name_value"`
	}

	var entries []CrtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return subdomains
	}

	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			cleanName := strings.TrimPrefix(name, "*.")
			if strings.Contains(cleanName, domain) {
				subdomains[cleanName] = struct{}{}
			}
		}
	}
	return subdomains
}

func analyzeHost(url string) (*ScanResult, bool) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "UNCLE_RECON/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false
	}
	htmlContent := string(body)

	titleMatch := titleRegex.FindStringSubmatch(htmlContent)
	title := ""
	if len(titleMatch) > 1 {
		title = strings.TrimSpace(titleMatch[1])
	}

	ipAddress := ""
	if addr, err := net.LookupIP(resp.Request.URL.Hostname()); err == nil && len(addr) > 0 {
		ipAddress = addr[0].String()
	}

	// Updated: Use Fingerprint instead of AnalyzeWithBody
	technologies := wappalyzerClient.Fingerprint(resp.Header, body)
	var techNames []string
	for tech := range technologies {
		techNames = append(techNames, tech)
	}
	sort.Strings(techNames)

	result := &ScanResult{
		URL:           url,
		StatusCode:    resp.StatusCode,
		ContentLength: len(body),
		Title:         title,
		IPAddress:     ipAddress,
		Technologies:  techNames,
	}

	return result, true
}

func parseMatchCodes(codesStr string) map[int]struct{} {
	codes := make(map[int]struct{})
	parts := strings.Split(codesStr, ",")
	for _, part := range parts {
		var code int
		_, err := fmt.Sscanf(strings.TrimSpace(part), "%d", &code)
		if err == nil {
			codes[code] = struct{}{}
		}
	}
	return codes
}

func saveOutput(results []ScanResult, filename string) {
	sort.Slice(results, func(i, j int) bool {
		return results[i].URL < results[j].URL
	})

	var builder strings.Builder
	for _, res := range results {
		techStr := "N/A"
		if len(res.Technologies) > 0 {
			techStr = strings.Join(res.Technologies, ",")
		}
		line := fmt.Sprintf("%s [%d] [%d] [%s] [%s] [%s]\n",
			res.URL, res.StatusCode, res.ContentLength, res.Title, res.IPAddress, techStr)
		builder.WriteString(line)
	}

	output := builder.String()
	if filename != "" {
		err := os.WriteFile(filename, []byte(output), 0644)
		if err != nil {
			log.Fatalf("[-] Failed to write output: %v", err)
		}
		fmt.Printf("[*] Results saved to %s\n", filename)
	} else {
		fmt.Println("\n--- Live Hosts ---")
		fmt.Print(output)
	}
}

