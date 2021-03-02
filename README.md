# RIP-Sniffer
Nástroje monitorující a generující zprávy jednoduchých distance-vectore protokolů

Projekt pro odposlech komunikace a podvrhnutí falesne RIPng zpravy.

Projekt je nutno rozbalit z adresare a nasledne ho prelozit prikazem make, ten prelozi obe dve casti projektu a vzniknou dva spustitelne soubory myripsniffer a myripresponse

Jejich sputeni je nasleující:

./myripsniffer -i <rozhrani>
* -i: <rozhrani> udava rozhrani, na kterem má byt odchyt paketu provaden

V pripade ze budeme program spoustet na fyzickem rozhrani (ve virt. stroji isa2015 je to eth0), je nutné provest spusteni jako root, cili vlozit pred prikaz sudo.


./myripresponse -i <rozhrani> -r <IPv6>/[16-128] {-n <IPv6>} {-m [0-16]} {-t [0-65535]}
kde význam parametrù je následující: 
* -i: <rozhrani> udává rozhraní, ze ktereho ma byt utocny paket odeslan;
* -r: v <IPv6> je IP adresa podvrhavane site a za lomitkem ciselna delka masky site;
* -m: nasledujici cislo udava RIP Metriku, tedy pocet hopu, implicitne 1;
* -n: <IPv6> za timto parametrem je adresa next-hopu pro podvrhavanou routu, implicitne ::;
* -t: cislo udava hodnotu Router Tagu, implicitne 0.

Parametry -n, -m a -t jsou nepovinne. V pripade ze posilame pres fyzicke rozhrani, je opet nutno pouzit sudo.

README
