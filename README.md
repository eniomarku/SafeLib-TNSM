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
  Please read README.md at https://github.com/eniomarku/SafeLib to see how to build and run Lib2. <br />
  Note that https://github.com/eniomarku/SafeLib-TNSM/SafeLib_Lib2 is a copy of https://github.com/eniomarku/SafeLib. <br />
  If you want to only use Lib2 of SafeLib we recommend you to clone https://github.com/eniomarku/SafeLib. <br />
  If you want to use both Lib2 and Lib3 of SafeLib we recommend you to clone https://github.com/eniomarku/SafeLib-TNSM.<br />
    
## Lib3
   This library is used for developing stateless VNFs, and securely outsourcing them into a third party provider. <br />
   Please read README.md at https://github.com/eniomarku/SafeLib-TNSM/tree/main/SafeLib_Lib3 to see how to build and run this library.
