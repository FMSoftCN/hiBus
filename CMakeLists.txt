CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

PROJECT(hibus C)

SET(PROJECT_NAME "hibus")
SET(PROJECT_VERSION "1.0.2")

ADD_DEFINITIONS(-O2 -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations -fmax-errors=10)

OPTION(BUILD_APP_AUTH "build with app authentication" ON)
OPTION(BUILD_PLUGIN "build support for plugin" ON)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

ADD_DEFINITIONS( -DHIBUS_VERSION="${PROJECT_VERSION}")

ADD_SUBDIRECTORY(src)

# Packing stuff
SET(CPACK_PACKAGE_VENDOR "FMSoft")
SET(CPACK_PACKAGE_NAME ${PROJECT_NAME})
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "The data bus server, library, and command line for device side of HybridOS")
SET(CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${PROJECT_VERSION}")
SET(CPACK_SOURCE_GENERATOR "TGZ")
SET(CPACK_SOURCE_IGNORE_FILES
      "/auto/;/cmake/;/.svn/;/.git/;/.bzr/;/CMakeFiles/;/_CPack_Packages/;CMakeCache.txt$;
      ~$;.swp$;.cmake$;
      ${CPACK_SOURCE_IGNORE_FILES}")

INCLUDE(CPack)

