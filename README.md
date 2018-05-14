# cGOOSE
C implementation of GOOSE protocol from IEC61850

## Directory Structure
* bin/        compiled executable files
* src/        source code files
* include/    header files
* doc/        doxygen documentation files
* lib/        third party library files
* Makefile    make file for the project

## Set-up on Ubuntu
Ubuntu 16.04.1 Desktop (64-bit) was used for the development work

* sudo apt-get install -y git git-man liberror-perl libpcap0.8-dev libpcap-dev libpcap0.8 doxygen valgrind gcc-arm-linux-gnueabi
* git clone https://github.com/kushfj/cGOOSE.git
* cd cGOOSE
* mkdir bin
* make

The steps above need to be extended to be able to compile the code for execution on a Raspberry Pi. To do this libpcap library for the arm processor is required to link to
* Download the latest libpcap source tar ball from [http://www.tcpdump.org/#latest-releases], e.g. libpcap-1.8.1.tar.gz
* tar zxvf libpcap-1.8.1.tar.gz
* apt-get install flex bison byacc
* export CC=arm-linux-gnueabi-gcc
* ./configure --host=arm-linux --with-pcap=linux
* make

Once the libpcap library has been compiled for the Arm processor, edit the src/Makefile to change the LDFLAG to the appropriate location for the pi-debug and pi-release targets

