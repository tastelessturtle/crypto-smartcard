CryptoApplet.cap: build.xml src/cryptoapplet/CryptoApplet.java src/cryptoapplet/ECDSA.java
	-java -jar tools/gp.jar --uninstall CryptoApplet.cap
	rm -f CryptoApplet
	ant
	java -jar tools/gp.jar --install CryptoApplet.cap
	pytest -s

test:
	pytest -s

clean:
	-java -jar tools/gp.jar --uninstall CryptoApplet.cap
	rm -f CryptoApplet.cap