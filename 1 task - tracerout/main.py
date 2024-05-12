from scapy.all import socket
import argparse
import prettytable
import os


def system_tracerout(addr):
    ip_host = socket.gethostbyname(addr)
    ans = []
    output = os.popen("tracert " + addr, "r")
    for line in output:
        line = line.split(" ")
        if len(line) > 2:
            if line[2].isdigit() or line[1].isdigit() or line[0].isdigit():
                if line[-1] == "\n":
                    ans.append(line[-2].strip("[]"))
    ans.append(ip_host)
    return ans


def whois(list_ip: list[str]) -> dict[str, dict[str, str]]:
    DEFAULT_RIR_LIST = ['ripe', 'arin', 'apnic', 'afrinic', 'lacnic']
    DEFAULT_PORT = 43

    def parse_ripe_apnic_afrinic(res: str) -> dict[str, str]:
        info = {}
        for line in res.splitlines():
            if line.startswith('descr:') and len(line[len('descr:'):].strip()) > 0:
                info['Description'] = line[len('descr:'):].strip()
            if line.startswith('country:') and len(line[len('country'):].strip()) > 0:
                info['Country'] = line[len('country:'):].strip()
            if line.startswith('origin:') and len(line[len('origin:'):].strip()) > 0:
                info['AS'] = line[len('origin:'):].strip()

        if len(info) == 3:
            return info

    def parse_arin(res: str) -> dict[str, str]:
        info = {}

        for line in res.splitlines():
            if line.startswith('OrgName:') and len(line[len('OrgName:'):].strip()) > 0:
                info["Description"] = line[len('OrgName:'):].strip()
            if line.startswith('Country:') and len(line[len('Country:'):].strip()) > 0:
                info["Country"] = line[len('Country:'):].strip()
            if line.startswith('OriginAS:') and len(line[len('OriginAS:'):].strip()) > 0:
                info["AS"] = line[len('OriginAS:'):].strip()

        if len(info) == 3:
            return info

    def parse_lacnic(res: str) -> dict[str, str]:
        info = {}
        for line in res.splitlines():
            if line.startswith('aut-num:') and len(line[len('aut-num'):].strip()) > 0:
                info["AS"] = line[len('aut-num:'):].strip()
            if line.startswith('country:') and len(line[len('country:'):].strip()) > 0:
                info['Country'] = line[len('country:'):].strip()
            if line.startswith('owner:') and len(line[len('owner:'):].strip()) > 0:
                info['Description'] = line[len('owner:'):].strip()

        if len(info) == 3:
            return info

    def parse_by_rir(rir: str, res: str) -> dict[str, str]:
        return parse_map[rir](res)

    parse_map = {DEFAULT_RIR_LIST[0]: parse_ripe_apnic_afrinic,
                 DEFAULT_RIR_LIST[1]: parse_arin,
                 DEFAULT_RIR_LIST[2]: parse_ripe_apnic_afrinic,
                 DEFAULT_RIR_LIST[3]: parse_ripe_apnic_afrinic,
                 DEFAULT_RIR_LIST[4]: parse_lacnic}

    def get_info(ip: str) -> dict[str, str]:
        for rir in DEFAULT_RIR_LIST:
            ans = ""
            rir_addr = f"whois.{rir}.net"
            sock = socket.create_connection((rir_addr, DEFAULT_PORT))
            sock.sendall(f'{ip}\n'.encode("utf-8"))

            while True:
                buf = sock.recv(1024).decode("latin-1")
                ans += buf
                if len(buf) == 0:
                    break
            result = parse_by_rir(rir, ans)

            if result:
                return result
        return {"Description": "", "Country": "", "AS": ""}

    def get_info_list_ip() -> dict[str, dict[str, str]]:
        ans = {}
        for ip in list_ip:
            ans[ip] = get_info(ip)
        return ans

    return get_info_list_ip()


def main():
    parser = argparse.ArgumentParser(prog='tracer',
                                     description='Trace to IP and do Whois for each IP in the trace path.')
    parser.add_argument('dst_ip', type=str, help='Destination IP address')
    args = parser.parse_args()

    table = prettytable.PrettyTable()
    table.field_names = ['IP', 'AS', 'Country', 'Description']

    trace = system_tracerout(args.dst_ip)
    w = whois(trace)

    for ip, descr in w.items():
        table.add_row([ip, descr['AS'], descr['Country'], descr['Description']])

    print(table)


if __name__ == "__main__":
    main()
