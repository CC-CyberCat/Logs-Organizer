import config
import csv
import re
from datetime import datetime
from config import UI   # cores para terminal

def convert(match):
    data_str = match.group(1)
    # Transforma a string em objeto datetime
    obj_data = datetime.strptime(data_str, "%d/%b/%Y:%H:%M:%S %z")
    # Devolve no formato Syslog
    return obj_data.strftime("%Y-%m-%d %H:%M:%S")


def change_datetime_apache(logs_path) -> list:
    processed_lines = []
    try:
        with open(logs_path, "r", encoding='utf-8') as f_in:
            for line in f_in:
                new_line = re.sub(config.APACHE_DATETIME_REGEX, convert, line)
                processed_lines.append(new_line)
        return processed_lines
    except FileNotFoundError:
        print("Erro: Ficheiro não encontrado.")
        return []


def update_eventos(eventos, ip_dic):
    for evento in eventos:
        ip = evento["ip"]
        if ip in ip_dic and len(ip_dic[ip]) > 0:
            evento["suspeito"] = True  # True se IP em dicionário suspeitos
            evento["motivo_suspeita"] = " + ".join(sorted(ip_dic[ip]))
            # sorted() — por alfabeto
            # join() — junta para string " + "


def export_csv(eventos):
    campos = ["timestamp", "nivel", "servico", "ip", "mensagem",
              "origem", "suspeito", "motivo_suspeita"]
    # campos — nomes das colunas, a sequência importa

    with open("logs_normalizados.csv", "w", newline="", encoding="utf-8") as f:
        # newline="" — para não ter linhas vazias em Windows
        # encoding="utf-8" — simbolos especiais

        writer = csv.DictWriter(f, fieldnames=campos, extrasaction="ignore")
        # DictWriter — write dicionarios como CSV
        # fieldnames — sequencia das colunas
        # extrasaction="ignore" — ignora os keys a mais no dicionário

        writer.writeheader()  # write pimeira linha com nomes das colunas
        writer.writerows(eventos)  # write eventos

    print(f"CSV exportado: {len(eventos)} eventos escritos.")
    # len(eventos) — comprimento eventos


def organize_it(logs: list) -> tuple:
    ssh_attempts = {}  # dicionario brute force ssh
    apache_errors = {}  # dicionario 2xx-5xx
    ip_dic = {}  # dicionario sem ‘items’ repetidos {ip: set(['brute force', 'scanning', 'madrugada'])}
                 # para uso no criterio 4
    total_alerts = 0  # contador de alertas
    madrugada_log = []  # List para acontecimentos a noite
    eventos = []  # lista de todos os eventos normalizados

    for line in logs:
        sr = config.SYSLOG_REGEX.search(line)
        ar = config.APACHE_REGEX.search(line)
        match = sr or ar  # procura syslog e apache ‘log’ nas linhas
        if not match: continue

        dt_str = match.group('datetime')
        alert_level = match.group('alert')

        # encontrar IP
        if ar:
            ip = ar.group('ip')
        else:
            ip_m = config.IP_REGEX.search(match.group('message'))
            ip = ip_m.group() if ip_m else 'N/A'

        # Atividade de madrugada
        hour = int(dt_str.split()[1].split(':')[0])  # dividir datetime por espaco(),
                                                     # retirar tempo[1], dividir tempo por (:), retirar hora [0]
        if 0 <= hour < 6:
            if ip not in ip_dic: ip_dic[ip] = set()  # cria ip: set()
            ip_dic[ip].add("madrugada")  # so adiciona uma vez
            time_only = dt_str.split()[1]  # retirar tempo

            if alert_level == "ERROR":
                msg = match.group('message')
                madrugada_log.append(
                    f"{UI.RED}{UI.BOLD}[CRÍTICO]{UI.RESET} Erro de madrugada: "
                    f"{UI.B_MAGENTA}{UI.BOLD}{ip}{UI.RESET} às {time_only} — {msg}")
            else:
                madrugada_log.append(
                    f"{UI.B_BLUE}{UI.BOLD}[SUSPEITO]{UI.RESET} Atividade fora de horas: "
                    f"{UI.B_MAGENTA}{UI.BOLD}{ip}{UI.RESET} às {time_only}")
            total_alerts += 1

        # determinar serviço
        if sr:
            servico = match.group('service')  # syslog service
            origem = "syslog"
        else:
            servico = "apache"  # apache não tem service
            origem = "apache"

        # criar evento normalizado
        evento = {
            "timestamp": dt_str,  # data e tempo
            "nivel": alert_level,  # INFO / WARNING / ERROR / код HTTP
            "servico": servico,  # sshd, apache e etc.
            "ip": ip,  # IP
            "mensagem": match.group('message'),  # mensagem
            "origem": origem,  # syslog ou apache
            "suspeito": False,  # não suspeito em default
            "motivo_suspeita": ""  # vazio por default
        }
        eventos.append(evento)  # tudo para lista

        # dados para criterios 1 e 2
        if sr and config.FAILED_PASSWORD.search(match.group('message')):
            ssh_attempts[ip] = ssh_attempts.get(ip, 0) + 1  # contagem erros de password
        elif ar and alert_level.startswith(('4', '5')):
            apache_errors[ip] = apache_errors.get(ip, 0) + 1  # contagem erros http

    tuple_events = (eventos, ip_dic, ssh_attempts, total_alerts, apache_errors, madrugada_log)
    return tuple_events


def output(tuple_events):
    (
        eventos,
        ip_dic,
        ssh_attempts,
        total_alerts,
        apache_errors,
        madrugada_log
    ) = tuple_events

    print(f"{UI.BOLD}\n{'=' * 40}\n  {'WHAT I FIND'.center(30)}\n{'=' * 40}\n{UI.RESET}")
    # Criterio 1
    print(f"\n{UI.BOLD}--- Brute force SSH {'-' * 30}")
    for ip, count in ssh_attempts.items():
        if count >= 5:  # se contagem de erros de password >= N
            total_alerts += 1
            if ip not in ip_dic: ip_dic[ip] = set()  # cria ip: set() se nao houver
            ip_dic[ip].add("brute force")
            print(f"{UI.RED}{UI.BOLD}[ALERTA]{UI.RESET} Possível brute force: "
                  f"{UI.B_MAGENTA}{UI.BOLD}{ip}{UI.RESET} — {count} tentativas falhadas")

    # Criterio 2
    print(f"\n{UI.BOLD}--- Scanning web (erros HTTP 4xx/5xx) {'-' * 15}")
    for ip, count in apache_errors.items():
        if count >= 4:
            total_alerts += 1
            if ip not in ip_dic: ip_dic[ip] = set()  # cria ip: set() se nao houver
            ip_dic[ip].add("scanning")
            print(f"{UI.RED}{UI.BOLD}[ALERTA]{UI.RESET} Possível scanning: "
                  f"{UI.B_MAGENTA}{UI.BOLD}{ip}{UI.RESET} — {count} erros HTTP (4xx/5xx)")

    # Criterio 3
    print(f"\n{UI.BOLD}---  Atividade de madrugada (00h-06h) {'-' * 18}")
    for log_line in madrugada_log:
        print(log_line)

    # Criterio 4
    print(f"\n{UI.BOLD}---  IPs altamente suspeitos (2+ critérios) {'-' * 12}")
    highly_susp_count = 0  # contador IPS perigosos
    for ip, flags in ip_dic.items():  # procura flags no set() do dicionario com ips e crimes.
        if len(flags) >= 2:
            highly_susp_count += 1
            sorted_flags = sorted(list(flags))
            print(f"{UI.RED}{UI.BOLD}[!!!] IP ALTAMENTE SUSPEITO: "
                  f"{UI.B_MAGENTA}{UI.BOLD}{ip}{UI.RESET} ({' + '.join(sorted_flags)})")