rule MINER_monero_mining_detection {

   meta:
      description = "Detect the risk of CoinMiner Monero Rule 1"
      detail= "Monero mining software"
   strings:
      $1 = "* COMMANDS:     'h' hashrate, 'p' pause, 'r' resume" fullword ascii
      $2 = "--cpu-affinity       set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" fullword ascii
      $3 = "* THREADS:      %d, %s, av=%d, %sdonate=%d%%%s" fullword ascii
      $4 = "--user-agent         set custom user-agent string for pool" fullword ascii
      $5 = "-O, --userpass=U:P       username:password pair for mining server" fullword ascii
      $6 = "--cpu-priority       set process priority (0 idle, 2 normal to 5 highest)" fullword ascii
      $7 = "-p, --pass=PASSWORD      password for mining server" fullword ascii
      $8 = "* VERSIONS:     XMRig/%s libuv/%s%s" fullword ascii
      $9 = "-k, --keepalive          send keepalived for prevent timeout (need pool support)" fullword ascii
      $10 = "--max-cpu-usage=N    maximum CPU usage for automatic threads mode (default 75)" fullword ascii
      $11 = "--nicehash           enable nicehash/xmrig-proxy support" fullword ascii
      $12 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
      $13 = "* CPU:          %s (%d) %sx64 %sAES-NI" fullword ascii
      $14 = "-r, --retries=N          number of times to retry before switch to backup server (default: 5)" fullword ascii
      $15 = "-B, --background         run the miner in the background" fullword ascii
      $16 = "* API PORT:     %d" fullword ascii
      $17 = "--api-access-token=T access token for API" fullword ascii
      $18 = "-t, --threads=N          number of miner threads" fullword ascii
      $19 = "--print-time=N       print hashrate report every N seconds" fullword ascii
      $20 = "-u, --user=USERNAME      username for mining server" fullword ascii
   
   condition:
   
      ( uint16(0) == 0x5a4d and
      filesize < 4000KB and
      ( 8 of them )) or
      ( all of them )
}

import "hash"

rule xmrig_moneroocean_prebuild: elf mining xmrig
{
    meta:
        description = "Detect the risk of CoinMiner Monero Rule 2"
    condition:
        hash.md5(0, filesize) == "5a818e75dff6adfe9f645cc49d6c0b70"
}

rule setup_moneroocean_miner: bash mining xmrig
{
    meta:
        description = "Detect the risk of CoinMiner Monero Rule 3"
    strings:
        $ = "MoneroOcean mining setup script"
        $ = "setup_moneroocean_miner.sh <wallet address>"
        $ = "TOTAL_CACHE=$(( $CPU_THREADS*$CPU_L1_CACHE + $CPU_SOCKETS"
        $ = "$HOME/moneroocean/xmrig"
        $ = "$LATEST_XMRIG_LINUX_RELEASE"
        $ = "moneroocean_miner.service"
    condition:
        any of them or hash.md5(0, filesize) == "75363103bb838ca8e975d318977c06eb"
}


rule uninstall_moneroocean_miner: bash mining xmrig
{
    meta:
      description = "Detect the risk of CoinMiner Monero Rule 4"
    strings:
        $default1 = "moneroocean"
        $default2 = "mining uninstall script"
        $s1 = "sudo systemctl stop"
        $s2 = "sudo systemctl disable"
        $s3 = "rm -f /etc/systemd/system/"
        $s4 = "sudo systemctl daemon-reload"
    condition:
        ($default1 or $default2) and any of ($s*) or hash.md5(0, filesize) == "b059718f365d30a559afacf2d86bc379"
}

rule moneroocean_miner_service: mining xmrig
{
    meta:
      description = "Detect the risk of CoinMiner Monero Rule 5"
    strings:
        $default1 = "ExecStart="
        $default2 = "moneroocean"
        $s1 = "[Service]"
        $s2 = "[Unit]"
    condition:
        all of ($default*) and any of ($s*)
}