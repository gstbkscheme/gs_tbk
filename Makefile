export LD_LIBRARY_PATH=./
CXX = g++
CC= gcc
all:
	#${CXX} -o test gstbk_test.cpp gs_tbk.cpp bn_pair.cpp   miracl.a -g
	${CXX} -o test gstbk_test.cpp gs_tbk.cpp bn_pair.cpp   miracl.a -O2
clean:
	rm -f test
