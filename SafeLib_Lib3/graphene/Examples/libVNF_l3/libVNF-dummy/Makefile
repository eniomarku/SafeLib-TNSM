all:
	gcc -fPIC -shared -o libl3vnfdummy.so.1 libvnf_dummy.c
	ln -s libl3vnfdummy.so.1 libl3vnfdummy.so

clean:
	rm -rf libl3vnfdummy.so*

distclean: clean
