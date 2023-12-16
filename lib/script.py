import threading, os, json, copy, psutil
from pathlib import Path
from signal import SIGKILL

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
            with open("/home/user/output.txt", "r") as fr:
                for line in fr:
                    event = json.loads(line)
                    if event["PID"] not in processes_events:
                        processes_events[event["PID"]] = set()
                    processes_events[event["PID"]].add(event["filename"])

def check_events() -> None:
    while True:
        with lock:
            for pid, filenames in processes_events.items():
                event_cve_2021_3493_check = copy.deepcopy(cve_2021_3493_check)
                for filename in filenames:
                    event_cve_2021_3493_check[filename] = True
                check_flag = 0
                for check in event_cve_2021_3493_check.values():
                    if not check:
                        continue
                    check_flag += 1
                # print(check_flag)
                if check_flag == 3:
                    # print(f"Try to kill process {pid}")
                    if psutil.pid_exists(int(pid)):
                        parent = int(pid) - 1
                        os.system(f"sudo kill -9 {parent}")
                        os.system(f"sudo kill -9 {pid}")

                        # okay
                        # parent_pid = psutil.Process(int(pid)).ppid()
                        # parent = psutil.Process(parent_pid)
                        # children = parent.children(recursive=True)
                        # for child in children:
                        #     print(f"Kill process {child.pid}")
                        #     child.kill()
                        # gone, still_alive = psutil.wait_procs(children, timeout=1)
                        # parent.kill()
                        # print(f"Kill process {parent.pid}")
                        # parent.wait(1)
                        # okay
                    # with open("/home/user/prevention.txt", "w") as fa:
                    #     fa.write(f"{pid}")
            # for pid, events in processes_events.items():
            #     event_cve_2021_3493_check = copy.deepcopy(cve_2021_3493_check)
            #     for event in events:
            #         event = json.loads(event)
            #         event_cve_2021_3493_check["filename"] = True
            #     check_flag = 0
            #     for check in event_cve_2021_3493_check.values():
            #         if not check:
            #             continue
            #         check_flag += 1
            #     if check_flag > 3:
            #         print(f"Try to kill process {pid}")
            #         os.system(f"kill -9 {pid}")
            #         # with open("/home/user/prevention.txt", "w") as fa:
            #         #     fa.write(f"{pid}")
                    
                        


def main() -> None:
    parse_event_thread = threading.Thread(target=parse_events)
    check_event_thread = threading.Thread(target=check_events)
    parse_event_thread.start()
    check_event_thread.start()
    parse_event_thread.join()
    check_event_thread.join()

if __name__ == "__main__":
    main()
