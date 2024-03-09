find_package(Poco REQUIRED COMPONENTS Foundation XML JSON Net NetSSL)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE Poco::Foundation Poco::Net Poco::NetSSL)
