CXX = g++
CXXFLAGS = -lmbedtls -lmbedcrypto -lmbedx509 -lpthread -lgtest -lgtest_main
SRC = test_ecc.cpp ecc.cpp ecdh.cpp
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


