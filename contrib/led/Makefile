install:
	install 90-lvfs-led.rules /etc/udev/rules.d
	install lvfs-led@.service /etc/systemd/system
	install lvfs-led.py /usr/bin
	udevadm control --reload
	systemctl daemon-reload

uninstall:
	rm -f /etc/udev/rules.d/90-lvfs-led.rules
	rm -f /etc/systemd/system/lvfs-led@.service
	rm -f /usr/bin/lvfs-led.py
	udevadm control --reload
	systemctl daemon-reload
