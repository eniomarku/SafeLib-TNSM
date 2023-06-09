# SafeLib-TNSM

SafeLib is a library used to securely outsource VNFs into a third party provider such as cloud environmnet. <br />
It is compromised of three libraries. 
## Lib1 
   This library is very simple and should mainly be used for outsourcing simple VNFs.<br />
   There is no repository of such library in our github because to use Lib1 no code is needed. <br />
   You simply need to prepare a manifest and run libVNF library inside graphene. <br />
   To build and run libVNF in kernel mode please check https://github.com/networkedsystemsIITB/libVNF/tree/release-socc.

## Lib2
  The source code of this library can be found in https://github.com/eniomarku/SafeLib. <br />
  This library is used to for developing stateful VNFs, and securely outsourcing them into a third party provider.<br />
  Please check README.md at https://github.com/eniomarku/SafeLib to see how to build and run Lib2. <br />
  Note that https://github.com/eniomarku/SafeLib-TNSM/tree/main/Lib2 is a submodule of https://github.com/eniomarku/SafeLib-TNSM. <br />
  If you want to only use Lib2 of SafeLib we recommend you to clone https://github.com/eniomarku/SafeLib. <br />
  If you want to use both Lib2 and Lib3 of SafeLib we recommend you to clone this repository using the following command;
  git clone https://github.com/eniomarku/SafeLib-TNSM --recursive <br />
    
## Lib3
   This library is used for developing stateless VNFs, and securely outsourcing them into a third party provider. <br />
   Please read README.md at https://github.com/eniomarku/SafeLib-TNSM/tree/main/SafeLib_Lib3 to see how to build and run this library.
   
# Features:

*	Written entirely in C/C++.
*	Provides integrity and confidentiality protection of user traffic, VNF policies, and integrity of VNF code.
*	Provides support for stateful VNFs.
*  Provides support for stateless VNFs.
*	Provides support for user-level TCP stack.
*	Provides support for kernel bypass mechanisms such as DPDK, netmap.


# Prerequisites
*	SafeLib makes use of Intel SGX, so first step is to make sure to run SafeLib on Intel CPU machines with support for SGX.
*	Make sure to have a machine with Linux as OS; we have tested our library only for Ubuntu 18.04, and 20.04 version.
*	Make sure to use a CPU and NIC supported by DPDK. The list of CPUs and NIC supported by DPDK can be found at http://core.dpdk.org/supported/ . For our testing purpose we have used Intel CPUs and “igb” drivers.
*	To run our scenarios physical machines are needed, which are interconnected via an ethernet cable. Only machines with VNFs deployed within SGX enclaves needs to have support for SGX.

# Preliminary steps:
*	Install Intel SGX driver/DCAP , SDK, and psw. To install them follow the instructions given in https://github.com/intel/linux-sgx
*	Make sure to have a machine with Linux as OS; we have tested our library only for Ubuntu 18.04, and 20.04 version.
*  Make sure to use a CPU and NIC supported by DPDK. The list of CPUs and NIC supported by DPDK can be found at http://core.dpdk.org/supported/. (For our testing purpose we have used Intel CPUs and “igb” drivers)
*	Install nasm 2.14 as follows;

 >> wget http://www.nasm.us/pub/nasm/releasebuilds/2.14.02/nasm-2.14.02.tar.xz \
 >> tar -xf ./nasm-2.14.02-xdoc.tar.xz –strip-components=1 \
 >> ./configure –prefix=/usr \
 >> make\
 >> make install
*	Install intel-ipsec-mb. Instructions can be found at https://github.com/intel/intel-ipsec-mb <br />
     ** Configure ipsec file (ipsec.cfg). One example of ipsec.cfg can be found at  https://github.com/eniomarku/SafeLib at (graphene/Examples/libVNF_epc/libVNF-release-socc/examples/epc/mme)
     
*	Install spdlog. Instructions can be found at https://github.com/gabime/spdlog
*	Install boost (libboost-all-dev)
*	Install libnuma, libpthread, librt, libgmp
*	Run the following command for building graphene dependencies: 
>> sudo apt-get install -y \   build-essential autoconf gawk bison wget python3 libcurl4-openssl-dev \
   python3-protobuf libprotobuf-c-dev protobuf-c-compiler

# Tested environment
 We have tested our library in the following environment:

* Ubuntu 18.04
5.3.0-28-generic kernel version
No Intel SGX DCAP
Intel(R) Core(TM) i7-8809G CPU @ 3.10GHz
b) We have tested our library also for the following environment:

* Ubuntu 20.04
5.9.0-050900rc6-generic kernel version
Intel SGX DCAP https://github.com/intel/SGXDataCenterAttestationPrimitives/
Note: For the second type of environment some changes are needed to be done in the current version of SafeLib published in this repository, as given below:

  - Uncomment the function static void netdev_no_ret_dummy at dpdk_iface.h <br />
  - Uncomment the part of the code between ridder added .... ridder closed at compat.h, and kni_dev.h (both part of dpdk)
 
# Contact Information
GitHub issue board is the preferred way to report bugs and ask questions about SafeLib.

For any question, please contact us at the details given below <br />
CONTACTS FOR THE AUTHORS\
enio.marku@ntnu.no\
biczok@crysys.hu

