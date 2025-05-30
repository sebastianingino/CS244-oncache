sudo apt update
sudo apt install iperf3 netperf clang libbpf-dev llvm make linux-tools-common linux-tools-generic linux-tools-$(uname -r) -y

sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm

curl -sS https://webi.sh/gh | sh
source ~/.config/envman/PATH.env

curl https://mise.run | sh

echo "eval \"\$(/users/ingino/.local/bin/mise activate bash)\"" >> ~/.bashrc

source ~/.bashrc

mise trust

mise install

`mise which pip` install -r requirements.txt
