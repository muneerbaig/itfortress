TPOT Installation 
### **1. Update and Install Prerequisites**

First, ensure your system is ready to handle HTTPS repositories.

sudo apt update
sudo apt install ca-certificates curl gnupg -y

### **2. Add Docker’s Official GPG Key**

This key ensures the software you download is authentic and hasn't been tampered with.

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

### **3. Add the Repository to Apt Sources**

Instead of a `.repo` file, Ubuntu uses a `.list` file. Run this command to automatically detect your Ubuntu version and add the correct repository:

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

### **4. Install Docker Engine**

Now that the repo is added, update your package list and install the actual Docker packages.

sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

### **Verification**

To make sure everything is running correctly before you start the T-Pot installation, run:
sudo docker run hello-world

### **Step 1: Freeing Port 22 for the Honeypot**

T-Pot’s Cowrie honeypot needs to listen on port 22 to catch attackers. You successfully moved your real Ubuntu SSH out of the way:

1. **Change SSH Port:** Edit `/etc/ssh/sshd_config` and set `Port 22222`.

Restart Service: Run sudo systemctl restart ssh.


Installtion Of the TPOT

https://github.com/telekom-security/tpotce

cd tpotce

cp env.example .env

sudo docker compose up -d

sudo docker ps

