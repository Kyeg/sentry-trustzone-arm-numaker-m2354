CXX = g++
CXXFLAGS = -lmbedtls -lmbedcrypto -lmbedx509 -lpthread -lgtest -lgtest_main
SRC = TestFlow.cpp flow_issue_u_ticket.cpp ../../environment.cpp flow_apply_u_ticket.cpp flow_open_session.cpp flow_issue_u_token.cpp
SRC1 = ../stage_worker/msg_generator.cpp ../stage_worker/msg_verifier.cpp ../stage_worker/msg_verifier_message.cpp ../stage_worker/msg_verifier_r_ticket.cpp ../stage_worker/msg_verifier_u_ticket.cpp ../stage_worker/msg_generator_r_ticket.cpp ../stage_worker/msg_generator_u_ticket.cpp ../stage_worker/executor.cpp ../stage_worker/generated_msg_storer.cpp ../stage_worker/msg_sender.cpp ../stage_worker/msg_receiver.cpp ../stage_worker/received_msg_storer.cpp  ../device_controller.cpp 
SRC2 = ../../resource/crypto/ecc.cpp ../../resource/crypto/ecdh.cpp ../../model/message_model/u_ticket.cpp ../../model/message_model/r_ticket.cpp ../../model/message_model/message.cpp ../../model/data_model/other_device.cpp ../../model/data_model/this_person.cpp ../../model/data_model/this_device.cpp ../../model/data_model/current_session.cpp
OBJ = $(SRC:.cpp=.o) $(SRC2:.cpp=.o) $(SRC1:.cpp=.o)
TARGET = my_program


$(TARGET): $(OBJ)
	$(CXX) $(OBJ) $(CXXFLAGS)  -o $(TARGET)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@


clean:
	rm -f $(OBJ) $(TARGET)

run:
	./$(TARGET)
	


