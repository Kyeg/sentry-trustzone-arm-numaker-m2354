CXX = g++
CXXFLAGS = -lmbedtls -lmbedcrypto -lmbedx509 -lpthread -lgtest -lgtest_main
SRC = Test_Stage.cpp msg_generator_u_ticket.cpp msg_generator_r_ticket.cpp msg_verifier_r_ticket.cpp msg_verifier_u_ticket.cpp msg_verifier_message.cpp msg_verifier.cpp msg_generator.cpp executor.cpp generated_msg_storer.cpp
SRC2 = ../../resource/crypto/ecc.cpp ../../resource/crypto/ecdh.cpp ../../model/message_model/u_ticket.cpp ../../model/message_model/r_ticket.cpp ../../model/message_model/message.cpp ../../model/data_model/other_device.cpp ../../model/data_model/this_person.cpp ../../model/data_model/this_device.cpp ../../model/data_model/current_session.cpp
OBJ = $(SRC:.cpp=.o) $(SRC2:.cpp=.o)
TARGET = my_program


$(TARGET): $(OBJ)
	$(CXX) $(OBJ) $(CXXFLAGS)  -o $(TARGET)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@


clean:
	rm -f $(OBJ) $(TARGET)

run:
	./$(TARGET)


