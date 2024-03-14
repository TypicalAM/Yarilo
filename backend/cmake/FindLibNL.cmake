find_path(LibNL_INCLUDE_DIR netlink/netlink.h
	/usr/include
	/usr/include/libnl3
	/usr/local/include
	/usr/local/include/libnl3
)

find_library(LibNL_LIBRARY NAMES nl nl-3)
find_library(LibNL_ROUTE_LIBRARY NAMES nl-route nl-route-3)
find_library(LibNL_NETFILTER_LIBRARY NAMES nl-nf nl-nf-3)
find_library(LibNL_GENL_LIBRARY NAMES nl-genl nl-genl-3)

if (LibNL_INCLUDE_DIR AND LibNL_LIBRARY)
	set(LibNL_FOUND TRUE)
endif (LibNL_INCLUDE_DIR AND LibNL_LIBRARY)

if (LibNL_FOUND)
	if (NOT LibNL_FIND_QUIETLY)
	set(LibNL_LIBRARIES ${LibNL_LIBRARY} ${LibNL_ROUTE_LIBRARY} ${LibNL_NETFILTER_LIBRARY} ${LibNL_GENL_LIBRARY})
        message(STATUS "Found netlink 3 libraries: ${LibNL_LIBRARIES}")
        message(STATUS "Found netlink 3 includes: ${LibNL_INCLUDE_DIR}")
		endif (NOT LibNL_FIND_QUIETLY)
ELSE (LibNL_FOUND)
	if (LibNL_FIND_REQUIRED)
		message(STATUS "Netlink version 3 development packages cannot be found.")
		message(STATUS "In Debian/Ubuntu, they may be called:")
		message(STATUS "libnl-3-dev libnl-genl-3dev libnl-nf-3-dev libnl-route-3-dev")
		message(FATAL_ERROR "Could not find netlink library.")
	endif (LibNL_FIND_REQUIRED)
endif (LibNL_FOUND)
