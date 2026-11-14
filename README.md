# CyberSec: Analisador de Logs e Detector de Brute Force

Ferramenta de análise defensiva (Blue Team / SIEM simplificado) desenvolvida para monitorar logs de servidores web, identificar tentativas repetidas de acesso não autorizado (HTTP 401/403) via Expressões Regulares (Regex) e exportar alertas estruturados em JSON para bloqueio automatizado.

## Tecnologias e Conceitos
* **Python 3 & Regex (`re`):** Parsing de alta velocidade em arquivos de log.
* **Segurança Defensiva (Blue Team):** Detecção de ataques de força bruta e varredura de diretórios (`/admin`).
* **JSON:** Exportação de incidentes para integração com firewalls ou dashboards.

## Como executar
1. Execute o script no terminal: `python detector_ameacas.py`
2. O relatório `relatorio_incidentes.json` será gerado com os IPs classificados como risco alto.