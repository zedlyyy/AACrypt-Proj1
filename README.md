# Advanced Applied Cryptography project assignment
Project for AACrypt-2026 by **Diogo Nunes** and **Pedro Galego**

# Como correr o projecto
Para correr cada parte, temos que indicar o pathing correto para cada uma das parte
Primeiramente, para compilar tudo fazemos:
- `javac part?/StreamServer/*.java part?/cipherSuites/*.java part?/UDPproxy/*.java`
? pode ser 1 ou 2 dependedo da parte do projeto que quremos compilar
Para correr o programa, primeiro executamos o servidor:
- `java -cp . part?.StreamServer.hjStreamServer localhost `
E de seguida executamos o nosso proxy:
- `java -cp . part?.UDPproxy.hjUDPproxy`
