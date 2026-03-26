MISP Integration with Wazuh - Deployment Guide

This guide covers the deployment of the MISP (Malware Information Sharing Platform) using Docker, which can then be integrated with Wazuh for threat intelligence sharing.

🐳 1. Installing the MISP Docker Image

Follow these steps to clone the official repository and set up the containerized environment.

Step A: Clone the Repository

Clone the misp-docker GitHub repository to your local machine:

git clone https://github.com/MISP/misp-docker
cd misp-docker


Step B: Environment Configuration

Copy the template environment file to create your active .env file:

cp template.env .env


Step C: Configure the Base URL

Edit the .env file to set your specific network configuration:
nano .env

Critical Step: Locate the MISP_BASEURL variable and update it to reflect the IP address of the machine you are running MISP on (e.g., MISP_BASEURL=https://10.10.30.55).


2. Launching MISP

Once you have configured the MISP_BASEURL, you can start the Docker environment

docker-compose up -d

Verification

You can check if the containers are running correctly with:

docker ps
