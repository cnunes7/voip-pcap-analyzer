# voip-pcap-analyzer

Analizador de capturas VoIP (pcap/pcapng) en Python, sin dependencias externas.
Diagnostica SIP, SDP, RTP, RTCP y DTMF: llamadas sin respuesta, cortes a 32 s,
audio unidireccional, pérdida/jitter, hosts SIP mudos, y atribuye responsabilidad.

## Uso

    python3 -I voip_pcap_analyzer.py captura.pcap --json analisis.json

Opciones: `--call <Call-ID>`, `--ladder`, `--max-calls N`, `--sip-port P`, `--local-ip IP`.

## Aviso

Este repositorio contiene solo el código. No subas capturas: contienen IPs,
números de teléfono y audio de terceros.
