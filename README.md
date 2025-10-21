UNCLE_RECON
A fast, dependency-free reconnaissance tool for bug bounty hunters, written in Go.
Features
Simple Installation: Install directly from GitHub with a single go install command.
Single Executable: Compile once, run anywhere. 
No dependencies.
Subdomain Discovery: Uses crt.sh to find subdomains.
Live Host Probing: Concurrently checks for live web servers.
Data Extraction: Grabs status code, page title, content length, and IP address.
Technology Fingerprinting: Uses the powerful engine from ProjectDiscovery's wappalyzergo library.
Status Code Filtering: Focus on the results you care about.
Fast: Built with Go's native concurrency (goroutines) for maximum speed.
InstallationStep 1: Install GoFirst, ensure you have Go installed on your system (version 1.18+ is recommended). If you don't, get it from the official Go website.
Step 2: Install the ToolWith Go installed, run this single command in your terminal.  go install github.com/vikas271205/UNCLE_RECON@latest
It now points directly to your repository.
(Optional) Step 3: Verify Your PATHIf you run uncle-recon and get a "command not found" error, add Go's bin directory to your PATH by adding this line to your shell's config file (e.g., ~/.bashrc or ~/.zshrc):export PATH=$PATH:$(go env GOPATH)/bin
Then, restart your terminal.UsageYou can now run the tool directly from your terminal, from any directory.uncle-recon -u <target_domain> [options]
Arguments-u (Required): The target domain you want to scan. (e.g., google.com, tesla.com).-o: The name of the file where you want to save the results. If omitted, results are printed to the terminal.-c: Sets concurrency (how many hosts to scan at once). Default: 50.-mc: Match one or more status codes, separated by commas (e.g., -mc 403,302,500).Examples1. Scan a target and print results to the console:uncle-recon -u example.com
2. Scan a target and save the output to results.txt:uncle-recon -u example.com -o results.txt
3. Scan with higher concurrency and filter for 403 and 500 status codes:uncle-recon -u example.com -c 100 -mc 403,500

