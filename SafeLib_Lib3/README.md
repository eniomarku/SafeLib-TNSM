# How to build Lib3
Note: Let say that direcotry where this library is cloned is /home/nuc/SafeLib/SafeLib_Lib3
- ## Install IPSec_MB
  To intall IPSEC_MB please follow the same instructions given at  https://github.com/eniomarku/SafeLib/blob/7283ee5d5a0653d16ba7e2c23fcade6364d68590/README.md
- ## Install Netmap and configure
   * To install netmap first go at https://github.com/luigirizzo/netmap and git clone the project
   * cd /home/nuc/SafeLib/SafeLib_Lib3/netmap
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
  * cd /home/nuc/SafeLib/SafeLib_Lib3/graphene/libnetmap-controller/
  * make distclean && make && cp libnetmapcontroller.so* /usr/lib/x86_64-linux-gnu/ 
  * cd /usr/lib/x86_64-linux-gnu/ && rm libnetmapcontroller.so && ln -s libnetmapcontroller.so.1 libnetmapcontroller.so
- ## Install gsgx driver
  * cd /home/nuc/SafeLib/SafeLib_Lib3/graphene/Pal/src/host/Linux-SGX/sgx-driver
  *  make && sudo insmod gsgx.ko
- ## Install Graphene
  * First install SGX Driver (Recommended location is in the root directory where you have cloned this project)
  * export ISGX_DRIVER_PATH="/home/nuc/SafeLib/SafeLib_Lib3/linux-sgx-driver/"
  * cd /home/nuc/SafeLib/SafeLib_Lib3/graphene
  * make SGX=1 distclean && make SGX=1 DEBUG=1
- ## Install libl3vnfdummy
  * cd /home/nuc/SafeLib/SafeLib_Lib3/graphene/Examples/libVNF_l3/libVNF-dummy/
  * make distclean && make && cp libl3vnfdummy.so* /usr/lib/x86_64-linux-gnu/ 
  * cd /usr/lib/x86_64-linux-gnu/ && rm libl3vnfdummy.so && ln -s libl3vnfdummy.so.1 libl3vnfdummy.so
- ## Install libVNF
  * cd /home/nuc/SafeLib/SafeLib_Lib3/graphene/Examples/libVNF_l3/libVNF-release-socc
  * rm -rf build && mkdir build && cd build && cmake .. -DSTACK=L3VNF && make && make install
 
- ## Build load_balancer executable
  * cd /home/nuc/SafeLib/SafeLib_Lib3/graphene/Examples/libVNF_l3/libVNF-release-socc/examples/LB 
  * rm -f load_balancer && ./run.sh && ls load_balancer
- ## Build pal_loader and Run
  * cd /home/nuc/SafeLib/SafeLib_Lib3/graphene/Examples/libVNF_l3/ 
  * cp libVNF-release-socc/examples/LB/load_balancer ./ 
  * make SGX=1 distclean && make SGX=1 && SGX=1 ./pal_loader load_balancer
 
 -## Run AB scenario
   Note: A and B needs to be installed in physical hardware machines, machine B needs to have SGX installed, machine A does not have to have SGX installed


