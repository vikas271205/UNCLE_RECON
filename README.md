UNCLE_RECON (Go Version)
A fast, dependency-free reconnaissance tool for bug bounty hunters, inspired by httpx and written in Go.
This tool compiles into a single executable file and can be installed with one command.
Features
Simple Installation: Install directly from GitHub with a single go install command.
Single Executable: Compile once, run anywhere. No dependencies.
Subdomain Discovery: Uses crt.sh to find subdomains.
Live Host Probing: Concurrently checks for live web servers.
Data Extraction: Grabs status code, page title, content length, and IP address.
Technology Fingerprinting: Uses the powerful engine from ProjectDiscovery's wappalyzergo library.
Status Code Filtering: Focus on the results you care about.
Fast: Built with Go's native concurrency (goroutines) for maximum speed.
httpx-like Output: Clean, single-line output for easy parsing.
Installation
Step 1: Install Go
First, ensure you have Go installed on your system (version 1.18+ is recommended). If you don't, get it from the official Go website.
Step 2: Install the Tool
With Go installed, run this single command in your terminal. Remember to replace YOUR_USERNAME with your actual GitHub username.
go install [github.com/YOUR_USERNAME/UNCLE_RECON@latest](https://github.com/YOUR_USERNAME/UNCLE_RECON@latest)


This command automatically downloads the source code from your GitHub repository, compiles it, and installs the uncle-recon binary in your Go path, ready to be used from anywhere.
(Optional) Step 3: Verify Your PATH
The go install command places the tool in your Go binary directory. For the uncle-recon command to work from any folder, this directory must be in your system's PATH.
It's usually configured automatically. If you run uncle-recon and get a "command not found" error, add Go's bin directory to your PATH by adding this line to your shell's config file (e.g., ~/.bashrc or ~/.zshrc):
export PATH=$PATH:$(go env GOPATH)/bin


Then, restart your terminal.
Usage
You can now run the tool directly from your terminal, from any directory.
uncle-recon -u <target_domain> [options]


Arguments
-u (Required): The target domain you want to scan. (e.g., google.com, tesla.com).
-o: The name of the file where you want to save the results. If omitted, results are printed to the terminal.
-c: Sets concurrency (how many hosts to scan at once). Default: 50.
-mc: Match one or more status codes, separated by commas (e.g., -mc 403,302,500).
Examples
1. Scan a target and print results to the console:
uncle-recon -u example.com


2. Scan a target and save the output to results.txt:
uncle-recon -u example.com -o results.txt


3. Scan with higher concurrency and filter for 403 and 500 status codes:
uncle-recon -u example.com -c 100 -mc 403,500


Example Output (results.txt)
URL [STATUS_CODE] [CONTENT_LENGTH] [PAGE_TITLE] [IP_ADDRESS] [TECHNOLOGIES]
[https://www.example.com](https://www.example.com) [200] [1256] [Example Domain] [93.184.216.34] [N/A]
[https://dev.example.com](https://dev.example.com) [403] [345] [Forbidden] [104.18.32.227] [Cloudflare]
[https://shop.example.com](https://shop.example.com) [302] [0] [] [172.64.148.11] [Nginx,PHP]



