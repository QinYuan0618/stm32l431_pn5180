PROJECT(NxpRdLib_CryptoASym)

FILE(GLOB NxpRdLib_CryptoASym_Sources
    ./src/phCryptoASym.c
    ./src/mBedTLS/phCryptoASym_mBedTLS.c
    ./src/mBedTLS/phCryptoASym_mBedTLS.h
    ./src/mBedTLS/phCryptoASym_mBedTLS_ECC.c
    ./src/mBedTLS/phCryptoASym_mBedTLS_ECC.h
    ./src/mBedTLS/phCryptoASym_mBedTLS_Hash.c
    ./src/mBedTLS/phCryptoASym_mBedTLS_Hash.h
    ./src/Stub/phCryptoASym_Stub.c
    ./src/Stub/phCryptoASym_Stub.h
)
ADD_LIBRARY(NxpRdLib_CryptoASym
    ${NxpRdLib_CryptoASym_Sources}
)
