# run after setting up the OBlivion Server
sudo brctl addif virbr0 tap0
sudo ifconfig tap0 192.168.0.5 up

