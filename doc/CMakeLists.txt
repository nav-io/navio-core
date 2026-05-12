# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

find_package(Doxygen COMPONENTS dot)

if(DOXYGEN_FOUND)
  set(doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
  configure_file(Doxyfile.in ${doxyfile} USE_SOURCE_PERMISSIONS)

  add_custom_target(docs
    COMMAND Doxygen::doxygen ${doxyfile}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMENT "Generating developer documentation"
    VERBATIM USES_TERMINAL
  )
else()
  add_custom_target(docs
    COMMAND ${CMAKE_COMMAND} -E echo "Error: Doxygen not found"
  )
endif()
