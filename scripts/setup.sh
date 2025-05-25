sudo apt update
sudo apt install iperf3 netperf clang libbpf-dev llvm make gh -y

sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm

curl https://mise.run | sh

echo "eval \"\$(/users/ingino/.local/bin/mise activate bash)\"" >> ~/.bashrc

source ~/.bashrc

mise trust

mise install

~/.local/share/mise/installs/python/3.13.3/bin/pip install -r requirements.txt
