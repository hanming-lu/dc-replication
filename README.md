# dc-replication
DataCapsule Replication for Paranoid Stateful Lambda (PSL) / Global Data Plane (GDP)

# How to build and run
Clone dc-replication repo
```
MY_PROJECT=~/dc-replication
git clone --recursive https://github.com/hanming-lu/dc-replication.git "${MY_PROJECT}"
```

Start docker (assuming docker is installed)
```
docker run -it --rm \
  --net=host \
  -v "${MY_PROJECT}":/opt/my-project \
  -w /opt/my-project \
  hanmingl/dc-replication:1.0
```

After entering the docker, build and run dcr-server within docker
```
mkdir -p build/ && cd build/
cmake ../src/
make -j4

./dcr-server
```
