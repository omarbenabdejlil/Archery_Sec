archery: setup run
	echo " Install all packages and run archerysec server "

setup:
	echo " install the packages needed and active venv"
	NAME=User EMAIL=user@user.com PASSWORD=admin@123A bash setup.sh

run:
	echo " running archerysec server "
	./run.sh