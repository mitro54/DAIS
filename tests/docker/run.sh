#!/bin/bash
echo "Building DAIS Ubuntu Test Environment..."
docker build -t dais-ubuntu .

echo "Starting Container on Port 2222..."
echo "You can connect using: ssh -p 2222 dais@localhost (Password: password)"
docker run -d --rm -p 2222:22 --name dais-test dais-ubuntu

echo "Done. Run 'docker stop dais-test' to clean up."
