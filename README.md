## Desafio 6 - INF01045

Ataque a um Diffie Hellman multiplicativo.

Arquivo1.txt contém texto cifrado com AES_ECB_128. A chave é obtida através da chave de sessão do DH.

DH Multiplicativo:
Alice e Bob concordam com um valor de n e g
Alice escolhe um valor x (secreto)
Bob escolhe um valor y (secreto)
Alice calcula X = x * g mod n (público)
Bob calcula Y = y * g mod n (público)
Alice e Bob trocam seus valores de X e Y
Alice usa Y e Bob usa X:
K = x * Y mod n = y * X mod n = x * y * g mod n

Eve: Capturou X, Y, g, n
Para obter K:
Note que: X * Y mod n => ((x * g mod n) * (y * g mod n)) mod n
=> x * g * y * g mod n => K * g mod n
Então:
1. Descobrir g-1
2. K = X * Y * g-1 mod n
