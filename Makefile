RM = rm -fv

CPPFLAGS += -ggdb -Wall -std=c++0x -I=. -Isrc -Iinclude

all: socket_lib

SRC=src/SocketClient.cpp src/SocketServer.cpp
OBJ = $(SRC:.cpp=.o)

socket_lib:$(OBJ)
	ar rcs libsocket.a $(OBJ)

clean:
	-$(RM) *.o 
