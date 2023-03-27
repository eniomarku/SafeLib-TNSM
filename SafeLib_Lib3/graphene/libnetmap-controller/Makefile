all:
	gcc -fPIC -shared -o libnetmapcontroller.so.1 libnetmap-controller.c
	ln -s libnetmapcontroller.so.1 libnetmapcontroller.so

clean:
	rm -rf libnetmapcontroller.so*

distclean: clean
