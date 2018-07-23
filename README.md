Como executar:

- Sniffer:

$ sudo python sniffer.py

Exemplo de saída:
$ sudo python sniffer.py
-- Sniffer v1.0 - Por Amilton e Dafny - 2016 --

Interfaces disponiveis sao:
['en0', 'awdl0', 'bridge0', 'en1', 'en2', 'p2p0', 'lo0']

Capturando em todas as interfaces...

[Capturado pacote #1] - (Pressione CTRL + C e aguarde para encerrar o programa)
2016-04-11 15:07:11.093142: capturados 46 bytes, truncado para 46 bytes
MAC de destino: 45:00:00:28:30:19 MAC de origem: 00:00:01:11:12:7b Protocolo: 5130
Versao: 8 Comprimento do cabecalho IP: 12 TTL: 20 Protocolo: 233 Endereco de origem: 218.193.0.0
Endereco de destino: 132.0.0.0
Obs.: Protocolo nao eh TCP/UDP/ICMP
...



- Scanner:

$ sudo python scanner.py

Exemplo de saída:
$ sudo python scanner.py
-- Scanner v1.0 - Por Amilton e Dafny - 2016 --

Interfaces disponiveis sao:
['lo0', 'gif0', 'stf0', 'en0', 'en1', 'en2', 'p2p0', 'awdl0', 'bridge0']

Usando a interface 'en0'...

Buscando hosts ativos na rede...

Host ativo: 10.20.142.172
Host ativo: 10.20.136.155
Host ativo: 10.20.138.45
Host ativo: 10.20.137.224
Host ativo: 10.20.141.181
...



Obs.: testados em ambiente MAC OS X.