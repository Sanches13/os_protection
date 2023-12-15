import threading, os, json, copy
from pathlib import Path

processes_events = dict()
events_file = "output.txt"
prevention_file = "prevention.txt"
cve_2021_3493_check = {"/proc/self/setgroups": False,
                       "/proc/self/uid_map": False,
                       "/proc/self/gid_map": False}
lock = threading.Lock()

def parse_events() -> None:
    while True:
        with lock:
            processes_events = {}
            with open("/home/user/output.txt", "r") as fr:
                for line in fr:
                    event = json.loads(line)
                    processes_events.setdefault(event["PID"], [])
                    processes_events[event["PID"]].append(event)

def check_events() -> None:
    while True:
        with lock:
            for pid, events in processes_events.items():
                event_cve_2021_3493_check = copy.deepcopy(cve_2021_3493_check)
                for event in events:
                    event = json.loads(event)
                    event_cve_2021_3493_check["filename"] = True
                check_flag = 0
                for check in event_cve_2021_3493_check.values():
                    if not check:
                        continue
                    check_flag += 1
                if check_flag == 3:
                    os.system("kill -9 %s", str(pid))
                    # with open("/home/user/prevention.txt", "w") as fa:
                    #     fa.write(f"{pid}")
                    
                        


def main() -> None:
    parse_event_thread = threading.Thread(target=parse_events)
    check_event_thread = threading.Thread(target=check_events)
    parse_event_thread.start()
    check_event_thread.start()
    parse_event_thread.join()
    check_event_thread.join()

if __name__ == "__main__":
    main()