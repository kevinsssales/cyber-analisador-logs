from collections import defaultdict
from datetime import datetime
import json
import re


def analisar_logs(caminho_arquivo, limite_tentativas=3):
  """Varre logs do servidor em busca de padrões de ataque Brute Force (Status 401/403)."""
  tentativas_falhas = defaultdict(int)
  padrao_log = re.compile(r"IP:\s([\d\.]+).*STATUS:\s(401|403)")

  with open(caminho_arquivo, "r", encoding="utf-8") as arquivo:
    for linha in arquivo:
      correspondencia = padrao_log.search(linha)
      if correspondencia:
        ip_suspeito = correspondencia.group(1)
        tentativas_falhas[ip_suspeito] += 1

  alertas = []
  for ip, total in tentativas_falhas.items():
    if total >= limite_tentativas:
      alertas.append({
          "ip_atacante": ip,
          "tentativas_bloqueadas": total,
          "nivel_risco": "ALTO",
          "acao_recomendada": "Bloquear IP no Firewall (WAF)",
          "timestamp_deteccao": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
      })

  return alertas


if __name__ == "__main__":
  print("Iniciando varredura de segurança nos logs...")
  incidentes = analisar_logs("servidor_acessos.log")

  with open("relatorio_incidentes.json", "w", encoding="utf-8") as saida:
    json.dump(incidentes, saida, ensure_ascii=False, indent=4)

  print(f"Varredura concluída! {len(incidentes)} ameaças críticas detectadas.")
  for alerta in incidentes:
    print(
        f"[ALERTA] IP: {alerta['ip_atacante']} | Falhas:"
        f" {alerta['tentativas_bloqueadas']} | Ação:"
        f" {alerta['acao_recomendada']}"
    )