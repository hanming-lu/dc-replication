# dc-replication
DataCapsule Replication for Paranoid Stateful Lambda (PSL) / Global Data Plane (GDP)

#### Install Protobuf
MacOS:
$brew install protobuf

#### Install libzmq from source 
cd third_party/libzmq/
./autogen.sh
./configure
make -j4
make -j4 install

#### Install cppzmq from source
cd third_party/cppzmq/
mkdir build
cd build
cmake ..
make -j4 install

