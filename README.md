# Advanced Applied Cryptography Project Assignment

## Overview

Advanced Applied Cryptography coursework exploring protected streaming communication in Java. The project is organized into two parts and includes a streaming server, cipher suite components, and a UDP proxy.

**Technologies:** Java, UDP networking, applied cryptography.

**Key components:** Streaming server, cryptographic cipher suites, UDP proxy.

---

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
