Docker Install Packages 

Install the packages:

apt install python3 python3-pip
pip3 install docker urllib3 requests


Add these conf agent ossec.conf

nano /var/ossec/etc/ossec.conf


<ossec_config>


  <wodle name="docker-listener">
    <interval>1m</interval>
    <attempts>5</attempts>
    <run_on_start>yes</run_on_start>
    <disabled>no</disabled>
  </wodle>
  
  
</ossec_config>

sudo systemctl restart wazuh-agent


Command Of the Docker Example:

sudo docker network create lab-net

1. Redis (In-Memory Database)

# CREATE
sudo docker create --name redis-lab -p 6379:6379 redis:alpine
# TAG
sudo docker tag redis:alpine redis:custom-cache
# START
sudo docker start redis-lab
# CONNECT
sudo docker network connect lab-net redis-lab
# EXEC
sudo docker exec -it redis-lab redis-cli ping
# TOP
sudo docker top redis-lab
# RESTART
sudo docker restart redis-lab
# DISCONNECT
sudo docker network disconnect lab-net redis-lab
# KILL
sudo docker kill redis-lab
# DIE (State verification)
sudo docker inspect --format='{{.State.Status}}' redis-lab
# STOP
sudo docker stop redis-lab
# UNTAG
sudo docker rmi redis:custom-cache
# DELETE
sudo docker rm redis-lab
# DESTROY (Force remove if stuck)
sudo docker rm -f redis-lab

2. Alpine Linux (Minimal OS)

# CREATE
sudo docker create --name alpine-shell alpine:latest tail -f /dev/null
# TAG
sudo docker tag alpine:latest alpine:base-image
# START
sudo docker start alpine-shell
# CONNECT
sudo docker network connect lab-net alpine-shell
# EXEC
sudo docker exec -it alpine-shell sh
# TOP
sudo docker top alpine-shell
# RESTART
sudo docker restart alpine-shell
# DISCONNECT
sudo docker network disconnect lab-net alpine-shell
# KILL
sudo docker kill alpine-shell
# DIE
sudo docker inspect --format='{{.State.Status}}' alpine-shell
# STOP
sudo docker stop alpine-shell
# UNTAG
sudo docker rmi alpine:base-image
# DELETE
sudo docker rm alpine-shell
# DESTROY
sudo docker rm -f alpine-shell


3. Apache HTTPD (Web Server)

# CREATE
sudo docker create --name apache-web -p 8081:80 httpd:alpine
# TAG
sudo docker tag httpd:alpine httpd:frontend
# START
sudo docker start apache-web
# CONNECT
sudo docker network connect lab-net apache-web
# EXEC
sudo docker exec -it apache-web httpd -v
# TOP
sudo docker top apache-web
# RESTART
sudo docker restart apache-web
# DISCONNECT
sudo docker network disconnect lab-net apache-web
# KILL
sudo docker kill apache-web
# DIE
sudo docker inspect --format='{{.State.Status}}' apache-web
# STOP
sudo docker stop apache-web
# UNTAG
sudo docker rmi httpd:frontend
# DELETE
sudo docker rm apache-web
# DESTROY
sudo docker rm -f apache-web


