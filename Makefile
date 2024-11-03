CryptoApplet.cap: build.xml src/CryptoApplet.java
	-java -jar tools/gp.jar --uninstall CryptoApplet.cap
	rm -f CryptoApplet
	ant
	java -jar tools/gp.jar --install CryptoApplet.cap
	python3 tests/main.py

test:
	python3 tests/main.py

clean:
	-java -jar tools/gp.jar --uninstall CryptoApplet.cap
	rm -f CryptoApplet.cap