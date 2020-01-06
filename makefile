CC = gcc -g
CFLAGS = -Wall
EXE = injection dummy

all : $(EXE)

.PHONY : clean	

$(EXE) : % : %.o dummy.o injection.o ptrace.o
	@echo "#---------------------------"
	@echo "# Generando $@ "
	@echo "# Depende de $^"
	@echo "# Ha cambiado $<"
	$(CC) $(CFLAGS) -o $@ $@.o ptrace.o

dummy.o : dummy.c
	@echo "#---------------------------"
	@echo "# Generando $@"
	@echo "# Depende de $^"
	@echo "# Ha cambiado $<"
	$(CC) $(CFLAGS) -c $<

injection.o : injection.c ptrace.h
	@echo "#---------------------------"
	@echo "# Generando $@"
	@echo "# Depende de $^"
	@echo "# Ha cambiado $<"
	$(CC) $(CFLAGS) -c $<

ptrace.o : ptrace.c ptrace.h
	@echo "#---------------------------"
	@echo "# Generando $@"
	@echo "# Depende de $^"
	@echo "# Ha cambiado $<"
	$(CC) $(CFLAGS) -c $<

clean :
	rm -rf *o
	rm -rf main
	rm -rf dummy
	rm -rf injection
	rm -rf a.out
