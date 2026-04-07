# multihttps
MultiThreaded Single FIle multi subdomain server

 Must be compiled after you choose the default bind adress or pass in as argument.
 afterwards, make the right path for the certificates,fullchain.pem and privkey.pem

 after that you set a HOME variable that is the folder in which all the sub domain folder sit, must end with a slash

 service file: /etc/systemd/system/itl_server.service
 [Unit]
Description=ITL Server Script
After=network.target

[Service]
ExecStart=/home/opaq/ITLC_https_v2-main/Backend/itl_server
Restart=on-failure
User=root
WorkingDirectory=/home/opaq/ITLC_https_v2-main/

# Write output to a file
StandardOutput=append:/home/opaq/itl_log.txt
StandardError=append:/home/opaq/itl_main_log.txt

[Install]
WantedBy=multi-user.target


once installed, run sudo systemctl daemon-reload
then sudo systemctl restart itl_server.service
