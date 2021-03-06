CC       = g++
CFLAGS   = -Wall -std=c11
LDFLAGS  = -lpthread
SRCS     = tcp_synflood.cpp
OBJFILES = tcp_synflood.o
TARGET   = tcp_synflood
INCLUDES = tcp_synflood.hpp

all: $(TARGET)
	mv *.o obj/

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

clean:
	rm -f $(OBJFILES) $(TARGET)

mrproper: clean
	rm -rf obj/*
	rm $(TARGET)

depend:
	makedepend -I. $(SRCS)

exe: $(TARGET)
	mv *.o obj/
	sudo ./$(TARGET)