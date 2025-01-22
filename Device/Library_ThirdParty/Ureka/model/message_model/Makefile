CXX = g++
CXXFLAGS = -lmbedtls -lmbedcrypto -lmbedx509 -lpthread -lgtest -lgtest_main
SRC = Test_Message_Model.cpp r_ticket.cpp u_ticket.cpp message.cpp
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


