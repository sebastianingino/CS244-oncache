sudo apt update
sudo apt install iperf3 clang libbpf-dev llvm make linux-tools-common linux-tools-generic -y

sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm

sudo apt install -y wget build-essential && wget https://github.com/HewlettPackard/netperf/archive/netperf-2.7.0.tar.gz && tar -zxvf netperf-2.7.0.tar.gz && (cd netperf-netperf-2.7.0/ && ./configure && make && sudo make install)

rm netperf-2.7.0.tar.gz
rm -rf netperf-netperf-2.7.0/

curl -sS https://webi.sh/gh | sh
source ~/.config/envman/PATH.env

curl https://mise.run | sh

echo "eval \"\$(/users/ingino/.local/bin/mise activate bash)\"" >> ~/.bashrc

source ~/.bashrc

mise trust

mise install

`mise which pip` install -r requirements.txt

git submodule update --init --recursive
