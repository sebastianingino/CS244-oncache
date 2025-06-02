# Download and install the latest mainline kernel script
wget https://raw.githubusercontent.com/pimlie/ubuntu-mainline-kernel.sh/master/ubuntu-mainline-kernel.sh
chmod +x ubuntu-mainline-kernel.sh

sudo ./ubuntu-mainline-kernel.sh -i v5.14.21

sudo sed -i -e 's/GRUB_DEFAULT=0/GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux 5.14.21-051421-generic"/' /etc/default/grub

sudo update-grub

sudo reboot now
