Install DFIR-IRIS and integration with WAZUH 

To run IRIS, follow these steps:

    Clone the iris-web repository:

    git clone https://github.com/dfir-iris/iris-web.git
    cd iris-web

Check out the latest non-beta tagged version: 

git checkout v2.4.27

Copy the environment file 

cp .env.model .env

Pull the Docker containers:

docker compose pull

Start IRIS:

# Add "-d" to put it in the background
docker compose up

If you don't find the password in the logs, try running 

docker compose logs app | grep "WARNING :: post_init :: create_safe_admin"

