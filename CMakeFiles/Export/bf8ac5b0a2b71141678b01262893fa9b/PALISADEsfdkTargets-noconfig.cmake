#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "PALISADEsfdk" for configuration ""
set_property(TARGET PALISADEsfdk APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(PALISADEsfdk PROPERTIES
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libPALISADEsfdk.0.1.0.dylib"
  IMPORTED_SONAME_NOCONFIG "@rpath/libPALISADEsfdk.0.dylib"
  )

list(APPEND _cmake_import_check_targets PALISADEsfdk )
list(APPEND _cmake_import_check_files_for_PALISADEsfdk "${_IMPORT_PREFIX}/lib/libPALISADEsfdk.0.1.0.dylib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
