# Advanced Applied Cryptography Project Assignment
Project for AACrypt-2026 by **Diogo Nunes** - 70502 and **Pedro Galego** - 72298 

# Como correr o projecto
Para correr cada parte, temos que indicar o pathing correto para cada uma das partes.
"?" pode ser 1 ou 2 dependedo da parte do projeto que queremos compilar.

Primeiramente, para compilar tudo fazemos:
- `javac part?/StreamServer/*.java part?/cipherSuites/*.java part?/UDPproxy/*.java`

Para correr o programa, primeiro executamos o servidor:
- `java -cp . part?.StreamServer.hjStreamServer localhost`

E de seguida executamos o nosso proxy:
- `java -cp . part?.UDPproxy.hjUDPproxy`
