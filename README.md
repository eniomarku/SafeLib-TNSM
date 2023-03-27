# SafeLib-TNSM

SafeLib is a library used to securely outsource VNFs into a third party provider such as cloud environmnet. SafeLib is compromised of three libraries.
## Lib1 
   This library is very simple and should mainly be used for outsourcing simple VNFs. There is no repository of such library in our github because to use Lib1 no code is needed
   You simply need to prepare a manifest and run libVNF library inside graphene.

## Lib2
    The source code of this library can be found in https://github.com/eniomarku/SafeLib
    This library is used to for developing stateful VNFs, and securely outsourcing them into a third party provider
    Please read README.md to see how to build and run Lib2
    
## Lib3
   This library is used for developing stateless VNFs, and securely outsourcing them into a third party provider
   Please read README.md to see how to build and run this library