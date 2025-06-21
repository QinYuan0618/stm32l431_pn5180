

PROJECT(NxpRdLib_alMfDuoX)

FILE(GLOB NxpRdLib_alMfDuoX_Sources
    ./src/phalMfDuoX.c
    ./src/phalMfDuoX_Int.c
    ./src/phalMfDuoX_Int.h
    ./src/Sw/phalMfDuoX_Sw.c
    ./src/Sw/phalMfDuoX_Sw.h
    ./src/Sw/phalMfDuoX_Sw_Int.c
    ./src/Sw/phalMfDuoX_Sw_Int.h
)
ADD_LIBRARY(${PROJECT_NAME}
    ${${PROJECT_NAME}_Sources}
)


TARGET_LINK_LIBRARIES(
    NxpRdLib_alMfDuoX
    NxpRdLib_TMIUtils
)
