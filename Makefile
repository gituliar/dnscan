check:
	@python3 dnscan.py check 1.com
	@python3 dnscan.py check gituliar.com
	@python3 dnscan.py check gituliar.net
	@python3 dnscan.py check narrativecode.com

scan-com:
	@python3 dnscan.py scan com

scan-net:
	@python3 dnscan.py scan net

install:
	sudo ln dnscand.service /etc/systemd/system/
	sudo chmod 644 /etc/systemd/system/dnscand.service
uninstall:
	sudo rm /etc/systemd/system/dnscand.service

start:
	sudo systemctl start dnscand.service
status:
	sudo systemctl status dnscand.service
stop:
	sudo systemctl stop dnscand.service

enable:
	sudo systemctl enable dnscand.service
disable:
	sudo systemctl disable dnscand.service
