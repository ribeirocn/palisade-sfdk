# - Config file for the PALISADEsfdk package
# It defines the following variables
#  SFDK_INCLUDE_DIRS - include directories for PALISADEabe
#  SFDK_LIBRARIES    - libraries to link against

get_filename_component(SFDK_CMAKE_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)

# Our library dependencies (contains definitions for IMPORTED targets)
if(NOT SFDK_BINARY_DIR)
  include("${SFDK_CMAKE_DIR}/PALISADEsfdkTargets.cmake")
endif()

# These are IMPORTED targets created by PALISADEsfdkTargets.cmake
set(SFDK_INCLUDE "/usr/local/include/palisade-sfdk")
set(SFDK_LIBDIR "/usr/local/lib")
set(SFDK_LIBRARIES PALISADEsfdk PALISADEcore;PALISADEpke;PALISADEbinfhe;-Xpreprocessor;-fopenmp;-lomp;-Wno-unused-command-line-argument  )
set(SFDK_STATIC_LIBRARIES  -Xpreprocessor;-fopenmp;-lomp;-Wno-unused-command-line-argument  )
set(SFDK_SHARED_LIBRARIES PALISADEsfdk PALISADEcore;PALISADEpke;PALISADEbinfhe;-Xpreprocessor;-fopenmp;-lomp;-Wno-unused-command-line-argument  )

set(OPENMP_INCLUDES "/usr/local/opt/libomp/include" )
set(OPENMP_LIBRARIES "/usr/local/opt/libomp/lib" )

set(SFDK_CXX_FLAGS " -Wall -Werror -O3  -DPALISADE_VERSION=1.11.7  -Wno-unused-private-field -Wno-shift-op-parentheses -DMATHBACKEND=2 -Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument -Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument -Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument -Wall -Werror -O3   -Wno-unused-private-field -Wno-shift-op-parentheses ")
set(SFDK_C_FLAGS " -Wall -Werror -O3  ")

set (SFDK_EXE_LINKER_FLAGS "   ")
