CXX = g++
CXXFLAGS = -lmbedtls -lmbedcrypto -lmbedx509 -lpthread -lgtest -lgtest_main
SRC = Test_Model.cpp current_session.cpp this_device.cpp this_person.cpp other_device.cpp ../../resource/crypto/ecc.cpp ../../resource/crypto/ecdh.cpp
OBJ = $(SRC:.cpp=.o)
TARGET = my_program


$(TARGET): $(OBJ)
	$(CXX) $(OBJ) $(CXXFLAGS)  -o $(TARGET)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@


clean:
	rm -f $(OBJ) $(TARGET)

run:
	./$(TARGET)


