# How to build Lib3
- ## Install IPSec_MB
  To intall IPSEC_MB please follow the same instructions given at  https://github.com/eniomarku/SafeLib/blob/7283ee5d5a0653d16ba7e2c23fcade6364d68590/README.md
- ## Install Netmap and configure
   * To install netmap first go at https://github.com/luigirizzo/netmap and git clone the project
   * cd netmap
   * make clean && make distclean
   * ./configure --no-drivers=mlx5 --enable-ptnetmap --enable-pipe --enable-monitor --enable-vale --drivers=igb --select-version=igb:5.3.5.18 
   * make && make install
    NIC=${ethInterface}
    IP=169.254.9.9 (Choose any IP you want, make sure the IP you choose is not used in your local network)
    NETMASK=255.255.255.0 (Recommended netmask but feel free to choose another one)
    NUMBUFS=1024
    sudo insmod ${netmap local location}/netmap.ko
    modprobe vxlan
    ethtool -G $NIC rx $NUMBUFS tx $NUMBUFS
    ifconfig $NIC $IP netmask $NETMASK
    sudo ifconfig $NIC up
- ## Install libnetmapcontroller
  * cd graphene/libnetmap-controller/ && make distclean && make && cp libnetmapcontroller.so /usr/lib/x86_64-linux-gnu/ 
  * cd /usr/lib/x86_64-linux-gnu/ && rm libnetmapcontroller.so && ln -s libnetmapcontroller.so.1 libnetmapcontroller.so
- ## Install gsgx driver
  * cd /graphene/Pal/src/host/Linux-SGX/sgx-driver
  *  make && sudo insmod gsgx.ko
- ## Install Graphene
  *First install SGX Driver (Recommended location is in the root directory where you have cloned this project)
- ## Install libl3vnfdummy
- ## Install libVNF
