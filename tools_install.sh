#!/usr/bin/env bash

echo "$(tput setaf  1)'
    ____                        ____  ____                    
   / __ \___  _________  ____  / __ \/ __ \_      _____  _____
  / /_/ / _ \/ ___/ __ \/ __ \/ /_/ / / / / | /| / / _ \/ ___/
 / _, _/  __/ /__/ /_/ / / / / ____/ /_/ /| |/ |/ /  __/ /    
/_/ |_|\___/\___/\____/_/ /_/_/    \____/ |__/|__/\___/_/     


          /  _/___  _____/ /_____ _/ / /__  _____             
          / // __ \/ ___/ __/ __  / / / _ \/ ___/             
        _/ // / / (__  ) /_/ /_/ / / /  __/ /                 
       /___/_/ /_/____/\__/\__,_/_/_/\___/_/                  
                                                              

$(tput sgr0)"


# TERM COLORS
bred='\033[1;31m'
bblue='\033[1;34m'
bgreen='\033[1;32m'
yellow='\033[0;33m'
red='\033[0;31m'
blue='\033[0;34m'
green='\033[0;32m'
reset='\033[0m'

# File descriptors
DEBUG_STD="&>/dev/null"
DEBUG_ERROR="2>/dev/null"

INSTALLATION_PATH=~/reconP0wer
TOOLS_PATH=~/tools
DEFAULT_SHELL=$HOME/.bashrc

if [[ $(id -u | grep -o '^0$') == "0" ]]; then
    SUDO=" "
else
    SUDO="sudo"
fi

setup_swap_file() {
	mem_size_in_gb=$(free --giga|grep Mem|cut -d":" -f2| awk '{ print $1}')
	printf "${bgreen} [+] System Memory Size: $mem_size_in_gb GB ${reset}\n"
	printf "${bgreen} [+] Making Swap File Size: $((mem_size_in_gb*2))GB ${reset}\n"
	eval $SUDO dd if=/dev/zero of=/swapfile bs=1024 count=$((mem_size_in_gb*2*1024*1024))k
	eval $SUDO chmod 0600 /swapfile
	eval $SUDO mkswap /swapfile
	eval $SUDO swapon /swapfile
	printf "${bgreen} [+] Enable swap partition ${reset}\n"
	printf "${bgreen} [+] Updating /etc/fstap file for swap partition ${reset}\n"
	echo "/swapfile none swap sw 0 0" >> /etc/fstab
	printf "${bgreen} [+] Swap enabled and ready to use ${reset}\n"
}

install_banner() {
	printf "${bblue} [+] $1 ${reset}\n\n"
}

go_installer(){
	version=go1.15.10
	eval type -P go $DEBUG_STD || { golang_installed=false; }
	printf "${bblue} Running: Installing/Updating Golang ${reset}\n\n"
	if [[ $(eval type go $DEBUG_ERROR | grep -o 'go is') == "go is" ]] && [ "$version" = $(go version | cut -d " " -f3) ]
		then
			printf "${bgreen} Golang is already installed and updated ${reset}\n\n"
		else
			eval $SUDO rm -rf /usr/local/go $DEBUG_STD
			if [ "True" = "$IS_ARM" ]; then
				eval wget https://dl.google.com/go/${version}.linux-armv6l.tar.gz --no-check-certificate $DEBUG_STD
				eval $SUDO tar -C /usr/local -xzf ${version}.linux-armv6l.tar.gz $DEBUG_STD
			else
				eval wget https://dl.google.com/go/${version}.linux-amd64.tar.gz --no-check-certificate $DEBUG_STD
				eval $SUDO tar -C /usr/local -xzf ${version}.linux-amd64.tar.gz $DEBUG_STD
			fi
			eval $SUDO cp /usr/local/go/bin/go /usr/bin
			rm -rf go$LATEST_GO*
			export GOROOT=/usr/local/go
			export GOPATH=$HOME/go
			export PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH
	cat << EOF >> ~/${profile_shell}
	# Golang vars
	export GOROOT=/usr/local/go
	export GOPATH=\$HOME/go
	export PATH=\$GOPATH/bin:\$GOROOT/bin:\$HOME/.local/bin:\$PATH
EOF

	fi

	[ -n "$GOPATH" ] || { printf "${bred} GOPATH env var not detected, add Golang env vars to your \$HOME/.bashrc or \$HOME/.zshrc:\n\n export GOROOT=/usr/local/go\n export GOPATH=\$HOME/go\n export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH\n\n"; exit 1; }
	[ -n "$GOROOT" ] || { printf "${bred} GOROOT env var not detected, add Golang env vars to your \$HOME/.bashrc or \$HOME/.zshrc:\n\n export GOROOT=/usr/local/go\n export GOPATH=\$HOME/go\n export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH\n\n"; exit 1; }
}

declare -A gotools
gotools["gf"]="go get -v github.com/tomnomnom/gf"
gotools["qsreplace"]="go get -v github.com/tomnomnom/qsreplace"
gotools["Amass"]="GO111MODULE=on go get -v github.com/OWASP/Amass/v3/..."
gotools["ffuf"]="go get -u github.com/ffuf/ffuf"
gotools["assetfinder"]="go get -v github.com/tomnomnom/assetfinder"
gotools["github-subdomains"]="go get -u github.com/gwen001/github-subdomains"
gotools["cf-check"]="go get -v github.com/dwisiswant0/cf-check"
gotools["waybackurls"]="go get -v github.com/tomnomnom/hacks/waybackurls"
gotools["nuclei"]="GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
gotools["anew"]="go get -v github.com/tomnomnom/anew"
gotools["notify"]="GO111MODULE=on go get -v github.com/projectdiscovery/notify/cmd/notify"
gotools["mildew"]="go get -u github.com/daehee/mildew/cmd/mildew"
gotools["dirdar"]="go get -u github.com/m4dm0e/dirdar"
gotools["unfurl"]="go get -v github.com/tomnomnom/unfurl"
gotools["httpx"]="GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx"
gotools["github-endpoints"]="go get -u github.com/gwen001/github-endpoints"
gotools["dnsx"]="GO111MODULE=on go get -v github.com/projectdiscovery/dnsx/cmd/dnsx"
gotools["subfinder"]="GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
gotools["gauplus"]="GO111MODULE=on go get -u -v github.com/bp0lr/gauplus"
gotools["subjs"]="GO111MODULE=on go get -u -v github.com/lc/subjs"
gotools["Gxss"]="go get -v github.com/KathanP19/Gxss"
gotools["gospider"]="go get -u github.com/jaeles-project/gospider"
gotools["crobat"]="go get -v github.com/cgboal/sonarsearch/crobat"
gotools["crlfuzz"]="GO111MODULE=on go get -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz"
gotools["dalfox"]="GO111MODULE=on go get -v github.com/hahwul/dalfox/v2"
gotools["puredns"]="GO111MODULE=on go get github.com/d3mondev/puredns/v2"
## added tools
gotools["gobuster"]="go install github.com/OJ/gobuster/v3@latest"
gotools["tko-subs"]="go get github.com/anshumanbh/tko-subs"
gotools["subzy"]="go get -u -v github.com/lukasikic/subzy; go install -v github.com/lukasikic/subzy"
gotools["goaltdns"]="go get github.com/subfinder/goaltdns"
gotools["filter-resolved"]="go get github.com/tomnomnom/hacks/filter-resolved"
gotools["metabigor"]="GO111MODULE=on go get github.com/j3ssie/metabigor"
gotools["just-resolved"]="go get github.com/j3ssie/go-auxs/just-resolved"
gotools["httprobe"]="go get -u github.com/tomnomnom/httprobe"
gotools["meg"]="go get -u github.com/tomnomnom/meg"
gotools["naabu"]="GO111MODULE=on go get -v github.com/projectdiscovery/naabu/v2/cmd/naabu"
gotools["shuffledns"]="GO111MODULE=on go get -v github.com/projectdiscovery/shuffledns/cmd/shuffledns"
gotools["dnsprobe"]="GO111MODULE=on go get -v github.com/projectdiscovery/dnsprobe"
gotools["subjack"]="go get github.com/haccer/subjack"
gotools["shhgit"]="go get github.com/eth0izzle/shhgit"
gotools["webanalyze"]="go get -v github.com/rverton/webanalyze/..."
gotools["gitleaks"]="GO111MODULE=on go get github.com/zricethezav/gitleaks/v7"

declare -A repos
repos["degoogle_hunter"]="six2dez/degoogle_hunter"
repos["pwndb"]="davidtavarez/pwndb"
repos["dnsvalidator"]="vortexau/dnsvalidator"
repos["dnsrecon"]="darkoperator/dnsrecon"
repos["theHarvester"]="laramies/theHarvester"
repos["brutespray"]="x90skysn3k/brutespray"
repos["wafw00f"]="EnableSecurity/wafw00f"
repos["Arjun"]="s0md3v/Arjun"
repos["gf"]="tomnomnom/gf"
repos["Gf-Patterns"]="1ndianl33t/Gf-Patterns"
repos["github-search"]="gwen001/github-search"
repos["ctfr"]="UnaPibaGeek/ctfr"
repos["LinkFinder"]="dark-warlord14/LinkFinder"
repos["ParamSpider"]="devanshbatham/ParamSpider"
repos["Corsy"]="s0md3v/Corsy"
repos["CMSeeK"]="Tuhinshubhra/CMSeeK"
repos["fav-up"]="pielco11/fav-up"
repos["Interlace"]="codingo/Interlace"
repos["massdns"]="blechschmidt/massdns"
repos["OpenRedireX"]="devanshbatham/OpenRedireX"
repos["GitDorker"]="obheda12/GitDorker"
repos["testssl"]="drwetter/testssl.sh"
repos["ip2provider"]="oldrho/ip2provider"

## added tools
repos["github-dorks"]="techgaun/github-dorks"
repos["CORStest"]="RUB-NDS/CORStest"
repos["JSParser"]="nahamsec/JSParser"
repos["Sublist3r"]="aboul3la/Sublist3r"
repos["Asnlookup"]="yassineaboukir/Asnlookup"
repos["gitGraber"]="hisxo/gitGraber"
repos["dnsgen"]="ProjectAnte/dnsgen"
repos["dnscan"]="rbsec/dnscan"
repos["sublert"]="yassineaboukir/sublert"
repos["dnsgen"]="ProjectAnte/dnsgen"
repos["dnsgen"]="ProjectAnte/dnsgen"
repos["dnsgen"]="ProjectAnte/dnsgen"


install_phantomjs(){
	PHANTOM_VERSION="phantomjs-2.1.1"
	if [ ! -n "$(command -v phantomjs)" ]; then
		printf "${bgreen} [+] Installing Phantomjs ${reset}"
		ARCH=$(uname -m)

		if ! [ $ARCH = "x86_64" ]; then
			$ARCH="i686"
		fi
		
		PHANTOM_JS="$PHANTOM_VERSION-linux-$ARCH"
		cd ~
		wget -q https://bitbucket.org/ariya/phantomjs/downloads/$PHANTOM_JS.tar.bz2
		eval $SUDO tar -xjf $PHANTOM_JS.tar.bz2
		rm $PHANTOM_JS.tar.bz2

		eval $SUDO mv $PHANTOM_JS /usr/local/share
		eval $SUDO ln -sf /usr/local/share/$PHANTOM_JS/bin/phantomjs /usr/local/bin
	else 
		printf "${bgreen} [+] Phantomjs Already installed!  ${reset}\n"
	fi
}

install_apt(){
	install_banner "Installing apt packages"
    eval $SUDO apt update -y $DEBUG_STD
	eval $SUDO apt-get update -qq
    eval $SUDO apt-get install chrpath libxft-dev -y -qq
    eval $SUDO apt-get install libfreetype6 libfreetype6-dev -y -qq
    eval $SUDO apt-get install libfontconfig1 libfontconfig1-dev -y -qq
	eval $SUDO apt install pigz -y -qq
	
	eval $SUDO apt install -y libpcap-dev $DEBUG_STD
    eval $SUDO apt install chromium-browser -y $DEBUG_STD
    eval $SUDO apt install chromium -y $DEBUG_STD
    eval $SUDO apt install python3 python3-pip ruby git curl libpcap-dev wget python3-dev python3-dnspython pv dnsutils build-essential libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap masscan jq python3-shodan apt-transport-https lynx tor medusa csvkit ripgrep unzip xsltproc httpie -y $DEBUG_STD
    eval $SUDO systemctl enable tor $DEBUG_STD
	eval $SUDO apt install python-dnspython awscli -y $DEBUG_STD
	
}

install_python_tools(){
	install_banner "python-tools"
	pip3 -q install setuptools 2>/dev/null
	pip3 -q install wheel 2>/dev/null
	pip3 -q install truffleHog 2>/dev/null
	install_banner "py-altdns" 2>/dev/null
	pip3 -q install py-altdns 2>/dev/null
	install_banner "wfuzz" 2>/dev/null
	pip3 -q install wfuzz 2>/dev/null
}

setup_dir_and_files(){
	install_banner "Setup directories" 
	mkdir -p $TOOLS_PATH
	mkdir -p $INSTALLATION_PATH/wordlists/ 2>/dev/null
	mkdir -p $INSTALLATION_PATH/wordlists/dns/ 2>/dev/null
	mkdir -p $INSTALLATION_PATH/wordlists/content/ 2>/dev/null
	mkdir -p $INSTALLATION_PATH/wordlists/params/ 2>/dev/null
	mkdir -p $INSTALLATION_PATH/signature/ 2>/dev/null
	mkdir -p $INSTALLATION_PATH/nmap-stuff/ 2>/dev/null
	mkdir -p $TOOLS_PATH/nmap-stuff/ 2>/dev/null
	mkdir -p ~/.gf
	mkdir -p ~/.config/notify/
	mkdir -p ~/.config/amass/
	mkdir -p ~/.config/nuclei/
}

download_wordlist(){
	install_banner "Downloading wordlist"

	[[ -f $INSTALLATION_PATH/wordlists/dns/all.txt ]] || wget -q -O $INSTALLATION_PATH/wordlists/dns/all.txt https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt

	[[ -f $INSTALLATION_PATH/wordlists/dns/commonspeak2-subdomains.txt ]] || wget -q -O $INSTALLATION_PATH/wordlists/dns/commonspeak2-subdomains.txt https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt

	[[ -f $INSTALLATION_PATH/wordlists/dns/shorts.txt ]] || wget -q -O $INSTALLATION_PATH/wordlists/dns/shorts.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt

	# permutation domain
	[[ -f $INSTALLATION_PATH/wordlists/dns/short-permutation.txt ]] || wget -q -O $INSTALLATION_PATH/wordlists/dns/short-permutation.txt https://raw.githubusercontent.com/5222222der/goaltdns/master/words.txt

	# vhost domain
	[[ -f $INSTALLATION_PATH/wordlists/dns/virtual-host-scanning.txt ]] || wget -q -O $INSTALLATION_PATH/wordlists/dns/virtual-host-scanning.txt https://raw.githubusercontent.com/codingo/VHostScan/master/VHostScan/wordlists/virtual-host-scanning.txt

	# content discovery
	[[ -f $INSTALLATION_PATH/wordlists/content/raft-large-directories.txt ]] || wget -q -O $INSTALLATION_PATH/wordlists/content/raft-large-directories.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt

	[[ -f $INSTALLATION_PATH/wordlists/content/quick.txt ]] || wget -q -O $INSTALLATION_PATH/wordlists/content/quick.txt https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt


	[[ -f $INSTALLATION_PATH/wordlists/content/top10000.txt ]] || wget -q -O $INSTALLATION_PATH/wordlists/content/top10000.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/RobotsDisallowed-Top1000.txt

	cat $INSTALLATION_PATH/wordlists/content/quick.txt $INSTALLATION_PATH/wordlists/content/top10000.txt > $INSTALLATION_PATH/wordlists/content/quick-content-discovery.txt

	[[ -f $INSTALLATION_PATH/wordlists/content/dir-all.txt ]] || wget -q -O $INSTALLATION_PATH/wordlists/content/dir-all.txt https://gist.githubusercontent.com/jhaddix/b80ea67d85c13206125806f0828f4d10/raw/c81a34fe84731430741e0463eb6076129c20c4c0/content_discovery_all.txt

	# params
	[[ -f $INSTALLATION_PATH/wordlists/params/param-miner.txt ]] || wget -q -O $INSTALLATION_PATH/wordlists/params/param-miner.txt https://raw.githubusercontent.com/PortSwigger/param-miner/master/resources/params

	[[ -f $INSTALLATION_PATH/wordlists/params/parameth.txt ]] || wget -q -O $INSTALLATION_PATH/wordlists/params/parameth.txt https://raw.githubusercontent.com/maK-/parameth/master/lists/all.txt

	cat $INSTALLATION_PATH/wordlists/params/param-miner.txt $INSTALLATION_PATH/wordlists/params/parameth.txt | sort -u > $INSTALLATION_PATH/wordlists/params/all.txt
	
	#aws s3 sync s3://assetnote-wordlists/data/ $INSTALLATION_PATH/wordlists/assetnote-wordlists --no-sign-request &> /dev/null

}

download_signatures(){
	install_banner "Downloading signatures"
	[[ -f $INSTALLATION_PATH/signature/providers-data.csv ]] || wget -q -O $INSTALLATION_PATH/providers-data.csv https://raw.githubusercontent.com/anshumanbh/tko-subs/master/providers-data.csv

	[[ -f $INSTALLATION_PATH/signature/fingerprints.json ]] || wget -q -O $INSTALLATION_PATH/fingerprints.json https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json

	# secret words to grep
	[[ -f $INSTALLATION_PATH/signature/keywords.txt ]] || wget -q -O $INSTALLATION_PATH/keywords.txt https://raw.githubusercontent.com/random-robbie/keywords/master/keywords.txt

	# resolvers
	[[ -f $INSTALLATION_PATH/signature/resolvers.txt ]] || wget -q -O $INSTALLATION_PATH/resolvers.txt https://raw.githubusercontent.com/Abss0x7tbh/bass/master/resolvers/public.txt
}

download_other_stuff(){
	install_banner "Downloading other stuff"
	[[ -f $INSTALLATION_PATH/signature/apps.json ]] || wget -q -O $INSTALLATION_PATH/apps.json https://raw.githubusercontent.com/AliasIO/Wappalyzer/master/src/apps.json

	# Nmap stuff
	install_banner "nmap vulners nse"
	# Install vulners nse script
	[[ -f $TOOLS_PATH/nmap-stuff/vulners.nse ]] || wget -q -O $TOOLS_PATH/nmap-stuff/vulners.nse https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse

	install_banner "nmap bootstrap"
	# Install nmap bootstrap
	[[ -f $TOOLS_PATH/nmap-stuff/nmap-bootstrap.xsl ]] || wget -q -O $TOOLS_PATH/nmap-stuff/nmap-bootstrap.xsl https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl

	install_banner "nmap & masscan parser"
	[[ -f $TOOLS_PATH/nmap-stuff/masscan_xml_parser.py ]] || wget -q -O $TOOLS_PATH/nmap-stuff/masscan_xml_parser.py https://raw.githubusercontent.com/laconicwolf/Masscan-to-CSV/master/masscan_xml_parser.py

	[[ -f $TOOLS_PATH/nmap-stuff/nmaptocsv.py ]] || wget -q -O $TOOLS_PATH/nmap-stuff/nmaptocsv.py https://raw.githubusercontent.com/maaaaz/nmaptocsv/master/nmaptocsv.py

	cd ~/tools
	## Special installation
	install_banner "findomain"
	eval wget -N -c https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux $DEBUG_STD
	eval $SUDO mv findomain-linux /usr/local/bin/findomain

	install_banner "gowitness"
	eval wget -N -c https://github.com/sensepost/gowitness/releases/download/2.3.4/gowitness-2.3.4-linux-amd64 $DEBUG_STD
	eval $SUDO mv gowitness-2.3.4-linux-amd64 /usr/local/bin/gowitness

	install_banner "DNScewl"
	eval wget -N -c https://github.com/codingo/DNSCewl/raw/master/DNScewl $DEBUG_STD
	eval $SUDO mv DNScewl /usr/local/bin/DNScewl

}

go_pkg_installer(){
	## Go PKG installer
	printf "${bblue} Running: Installing Golang tools (${#gotools[@]})${reset}\n\n"
	go_step=0
	for gotool in "${!gotools[@]}"; do
		go_step=$((go_step + 1))
		printf "${green} [+] Installing $gotool (${go_step}/${#gotools[@]})${reset}"
		eval type -P $gotool $DEBUG_STD || { eval ${gotools[$gotool]} $DEBUG_STD; }
		exit_status=$?
		if [ $exit_status -eq 0 ]
		then
			printf "${green} \xE2\x9C\x94 ${reset}\n"
		else
			printf "${red} X ${yellow}Unable to install, try manually ${reset}\n"
		fi
	done

	
}

repo_installer(){
	# Standard repos installation
	printf "${bblue} Running: Installing tools from github (${#repos[@]})${reset}\n\n"
	repos_step=0
	for repo in "${!repos[@]}"; do
		repos_step=$((repos_step + 1))
		printf "${green} [+] Installing $repo (${repos_step}/${#repos[@]})${reset}"
		eval cd $TOOLS_PATH/$repo $DEBUG_STD || { eval git clone https://github.com/${repos[$repo]} $TOOLS_PATH/$repo $DEBUG_STD && cd $TOOLS_PATH/$repo; }
		eval git pull $DEBUG_STD
		exit_status=$?
		if [ $exit_status -eq 0 ]
		then
			printf "${green} \xE2\x9C\x94 ${reset}\n"
		else
			printf "${red} X ${yellow}Unable to install, try manually ${reset}\n"
		fi
		if [ -s "setup.py" ]; then
			eval $SUDO python3 setup.py install $DEBUG_STD
		fi
		if [ "massdns" = "$repo" ]; then
				eval make $DEBUG_STD && strip -s bin/massdns && eval $SUDO cp bin/massdns /usr/bin/ $DEBUG_ERROR
		elif [ "gf" = "$repo" ]; then
				eval cp -r examples ~/.gf $DEBUG_ERROR
		elif [ "Gf-Patterns" = "$repo" ]; then
				eval mv *.json ~/.gf $DEBUG_ERROR
		fi
		cd $TOOLS_PATH
	done
}

start=`date +%s`
setup_dir_and_files
install_apt
go_installer
go_pkg_installer
repo_installer
install_phantomjs
install_python_tools
download_signatures
download_other_stuff
download_wordlist
end=`date +%s`

dt=$(echo "$end - $start" | bc)
dd=$(echo "$dt/86400" | bc)
dt2=$(echo "$dt-86400*$dd" | bc)
dh=$(echo "$dt2/3600" | bc)
dt3=$(echo "$dt2-3600*$dh" | bc)
dm=$(echo "$dt3/60" | bc)
ds=$(echo "$dt3-60*$dm" | bc)

printf "${green} Installation completed!\n"
LC_NUMERIC=C printf "Total runtime: %d:%02d:%02d:%02.4f\n" $dd $dh $dm $ds

