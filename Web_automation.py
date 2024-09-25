import subprocess
import os

def run_command(command):
    subprocess.run(command, shell=True)

def main():
    url = input("Enter the target URL: ")
    
    if not os.path.exists(url):
        os.mkdir(url)
    if not os.path.exists(f"{url}/recon"):
        os.mkdir(f"{url}/recon")
    if not os.path.exists(f"{url}/recon/scans"):
        os.mkdir(f"{url}/recon/scans")
    if not os.path.exists(f"{url}/recon/httprobe"):
        os.mkdir(f"{url}/recon/httprobe")
    if not os.path.exists(f"{url}/recon/potential_takeovers"):
        os.mkdir(f"{url}/recon/potential_takeovers")
    if not os.path.exists(f"{url}/recon/wayback"):
        os.mkdir(f"{url}/recon/wayback")
    if not os.path.exists(f"{url}/recon/wayback/params"):
        os.mkdir(f"{url}/recon/wayback/params")
    if not os.path.exists(f"{url}/recon/wayback/extensions"):
        os.mkdir(f"{url}/recon/wayback/extensions")
    
    if not os.path.exists(f"{url}/recon/httprobe/alive.txt"):
        open(f"{url}/recon/httprobe/alive.txt", "w").close()
    if not os.path.exists(f"{url}/recon/final.txt"):
        open(f"{url}/recon/final.txt", "w").close()

    # Harvesting subdomains with assetfinder
    run_command(f"assetfinder {url} >> {url}/recon/assets.txt")
    run_command(f"cat {url}/recon/assets.txt | grep {url} >> {url}/recon/final.txt")
    os.remove(f"{url}/recon/assets.txt")

    # Double checking for subdomains with amass
    run_command(f"amass enum -d {url} >> {url}/recon/f.txt")
    run_command(f"sort -u {url}/recon/f.txt >> {url}/recon/final.txt")
    os.remove(f"{url}/recon/f.txt")

    # Probing for alive domains
    run_command(f"cat {url}/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> {url}/recon/httprobe/a.txt")
    run_command(f"sort -u {url}/recon/httprobe/a.txt > {url}/recon/httprobe/alive.txt")
    os.remove(f"{url}/recon/httprobe/a.txt")

    # Checking for possible subdomain takeover
    if not os.path.exists(f"{url}/recon/potential_takeovers/potential_takeovers.txt"):
        open(f"{url}/recon/potential_takeovers/potential_takeovers.txt", "w").close()
    run_command(f"subjack -w {url}/recon/final.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o {url}/recon/potential_takeovers/potential_takeovers.txt")

    # Scanning for open ports
    run_command(f"nmap -iL {url}/recon/httprobe/alive.txt -T4 -oA {url}/recon/scans/scanned.txt")

    # Scraping wayback data
    run_command(f"cat {url}/recon/final.txt | waybackurls >> {url}/recon/wayback/wayback_output.txt")
    run_command(f"sort -u {url}/recon/wayback/wayback_output.txt")

    # Pulling and compiling all possible params found in wayback data
    run_command(f"cat {url}/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> {url}/recon/wayback/params/wayback_params.txt")
    with open(f"{url}/recon/wayback/params/wayback_params.txt", "r") as params_file:
        for line in params_file:
            print(f"{line.strip()}=")

    # Pulling and compiling js/php/aspx/jsp/json files from wayback output
    extensions = ["js", "html", "json", "php", "aspx"]
    for ext in extensions:
        with open(f"{url}/recon/wayback/extensions/{ext}.txt", "w") as ext_file:
            for line in open(f"{url}/recon/wayback/wayback_output.txt", "r"):
                if line.strip().endswith(f".{ext}"):
                    ext_file.write(line)
        os.remove(f"{url}/recon/wayback/extensions/{ext}.txt")

    print("[+] Recon Stage Completed :)")

if __name__ == "__main__":
    main()
