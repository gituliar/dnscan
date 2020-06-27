install:
	cp dnscan.service /etc/systemd/system/
	cp dnscan.timer /etc/systemd/system/
enable:
	systemctl daemon-reload
	systemctl enable dnscan.timer
	systemctl start dnscan.service
