import threading
import serial
import time
import json
from typing import Dict, List
from ureka_framework.logic.device_controller import DeviceController
import ureka_framework.model.data_model.this_device as this_device
import ureka_framework.model.message_model.u_ticket as u_ticket
import ureka_framework
import ureka_framework.environment as environment
import shutil
import os
import logging
import regex as re
from pprint import pprint
import inquirer


# Serial Port Setting
serial_port_name = 'COM3'
# serial_port_name = '/dev/ttyp0'
baud_rate = 115200
timeout = 1

def expand_nested_json(data):
    # 檢查每個鍵值對，嘗試解析內層 JSON 字串
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str):
                try:
                    # 嘗試將值解析為 JSON，若成功則展開
                    nested_json = json.loads(value)
                    data[key] = expand_nested_json(nested_json)
                except json.JSONDecodeError:
                    # 若解析失敗，表示不是 JSON 字串，保留原值
                    pass
            elif isinstance(value, dict) or isinstance(value, list):
                # 若值是字典或清單，則遞迴處理
                data[key] = expand_nested_json(value)
    elif isinstance(data, list):
        # 若資料是清單，則遞迴處理每個元素
        data = [expand_nested_json(item) for item in data]

    return data

def print_nested_json(json_message):
    # 將輸入的 JSON 字串轉換為字典
    data = json.loads(json_message)
    # 展開所有嵌套的 JSON 字串
    expanded_data = expand_nested_json(data)
    # 以可讀格式輸出
    print("Ticket json format: \n" + json.dumps(expanded_data, indent=2, ensure_ascii=False))

# Open Serial
file_handler = logging.FileHandler(f'agents.log')
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger = logging.getLogger('agents')
logger.addHandler(file_handler)
logger.setLevel(logging.DEBUG)
open(f'agents.log', 'w').close()
        

def dict_to_jsonstr(dict_obj: Dict[str, str]) -> str:
    return json.dumps(dict_obj, sort_keys=True)

def process_parsed_json(parsed_json):
    # Outer json
    message_type = parsed_json.get('message_type', 'Unknown')
    message_operation = parsed_json.get('message_operation', 'Unknown')
    if message_type != "RTICKET":
        return
    # Inner json
    inner_json = {}
    if 'message_json' in parsed_json:
        inner_json = parsed_json['message_json']
    elif 'message_str' in parsed_json:
        try:
            inner_json = json.loads(parsed_json['message_str'], strict=True)
        except json.JSONDecodeError:
            print(parsed_json['message_str'])
            print("[Agent] Parsing json ERROR")
    

def unescape_json(json_str):
    return json_str.replace('\\"', '"').replace("\\'", "'")

def parse_complex_log(log_data):
    json_pattern = r'\{(?:[^{}]|(?R))*\}'
    
    json_matches = re.findall(json_pattern, log_data, re.DOTALL)

    last_json = ""
    
    for json_str in json_matches:
        try:
            parsed_json = json.loads(json_str, strict=True)
            # print(json.dumps(parsed_json, indent=2, ensure_ascii=False))
            
            # Incase there is inner json
            # if 'message_str' in parsed_json:
            #     try:
            #         message_json = json.loads(unescape_json(parsed_json['message_str']))
            #         parsed_json['message_str'] = message_json
            #         # print(json.dumps(message_json, indent=2, ensure_ascii=False))
            #     except json.JSONDecodeError as e:
            #         print(f"[Agent] Json parsing ERROR: {e}")
            
            # print("+-------------------------------------------------------------+")
            # print("\n[Agent] Original Json:")
            # print(json.dumps(parsed_json, indent=2, ensure_ascii=False))
            process_parsed_json(parsed_json)
            if 'message_type' in parsed_json:
                # print("哈", json_str)
                last_json = json_str if parsed_json['message_type'] == "RTICKET" else last_json
        except json.JSONDecodeError as e:
            print(f"[Agent]Json parsing ERROR: {e}\n{json_str}")
    if last_json == "":
        # raise RuntimeError("No RTICKET received")
        return None
    else :
        # print("last_json", last_json)
        # dump last_json and print it out with indent
        print(f"[Agent] Received: ")
        print_nested_json(last_json)
    return last_json

class MySerial:
    def __init__(self, port, baudrate, device_manager, timeout=1):
        self.serial_port = serial.Serial(port=port, baudrate=baudrate, timeout=timeout)
        self.device_manager = device_manager
        self.running = False
    def send_data(self, message):
        print(f"[Agent] Sending: ")
        print_nested_json(message)
        # print(message)
        self.serial_port.write(f"{message}$\n".encode('utf-8'))
        self.serial_port.flush()

        # print("send_data", environment.my_ticket)
        environment.initialize()

    def start_reading(self):
        """開始執行緒來讀取 serial port 資料"""
        self.running = True
        self.thread = threading.Thread(target=self.read_from_serial)
        self.thread.start()

    def stop_reading(self):
        """停止讀取 serial port 並關閉執行緒"""
        self.running = False
        if self.thread.is_alive():
            self.thread.join()
        self.serial_port.close()
    def process_data(self, data):
        if self.device_manager.cummunicating_agent is None:
            logging.error("No communicating agent")
            return
        # logger.debug(f"[{self.device_manager.agents[self.device_manager.cummunicating_agent].shared_data.this_device.device_name}] Received data: {data}")
        received_json = parse_complex_log(data)
        # check if permissionless
        if received_json is None:
            return
        
        ticket_json = json.loads(received_json)
        if ticket_json["message_operation"] == "PERMISSIONLESS":
            self.device_manager.cummunicating_agent = None
            return

        environment.my_ticket = received_json
        

        self.device_manager.agents[self.device_manager.cummunicating_agent].msg_receiver._recv_xxx_message()
        if(environment.my_ticket):
            self.send_data(environment.my_ticket)
        else:
            self.device_manager.cummunicating_agent = None



    def read_from_serial(self):
        """在執行緒中不斷讀取 serial port 資料，並使用回呼函數處理資料"""
        while self.running:
            data = ""
            if self.serial_port.in_waiting:  # 有資料時讀取

                tmp_data = self.serial_port.read(1500000).decode('utf-8', errors='ignore')
                print("[Agent] Received: "+ tmp_data)
                data += tmp_data
                if data[-1] == '$':  # 以換行符號判斷資料結尾
                    self.process_data(data)  # 呼叫回呼函數處理資料
                    data = ""
            time.sleep(0.5)  # 防止 CPU 使用過高

    
class DeviceManager:
    def __init__(self):
        self.agents: List[DeviceController] = []
        self.cummunicating_agent: int = None
        self.my_serial = None
        self.types = ["init", "own", "saccess", "access", "permissionless"]
        self.agent_name = ["Manufacturer", "Admin", "User1", "User2", "User3", "User4", "User5", "User6", "User7", "User8", "User9", "User10", "User11", "User12", "User13", "User14", "User15", "User16", "User17", "User18", "User19", "User20"
                           , "User21", "User22", "User23", "User24", "User25", "User26", "User27", "User28", "User29", "User30", "User31", "User32", "User33", "User34", "User35", "User36", "User37", "User38", "User39", "User40", "User41", "User42", "User43", "User44", "User45", "User46", "User47", "User48", "User49", "User50"]




        
        self.remove_storage()
        environment.initialize()
        self.init_all_agents()
    def remove_storage(self):
        # Define the path to the SimpleStorage folder
        # Get the current script directory
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # Define the path to the SimpleStorage folder relative to the current directory
        folder_path = os.path.join(current_dir, 'ureka_framework', 'resource', 'storage', 'SimpleStorage')
        # Check if the folder exists
        if os.path.exists(folder_path):
            # Remove all contents of the SimpleStorage folder
            for item in os.listdir(folder_path):
                item_path = os.path.join(folder_path, item)
                try:
                    if os.path.isfile(item_path):
                        os.remove(item_path)
                        logger.info(f"Removed file: {item_path}")
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                        logger.info(f"Removed folder: {item_path}")
                except OSError as e:
                    logger.error(f"Error removing {item_path}: {e}")
        else:
            logger.info(f"Folder does not exist: {folder_path}")
    def init_all_agents(self):
        # 0: cloud_server_dm, 1: user1, 2: user2, 3: user3, -1: iot_device
        for i in range((len(self.agent_name))):
            agent: DeviceController = DeviceController(
                device_type=this_device.USER_AGENT_OR_CLOUD_SERVER,
                device_name=f"{self.agent_name[i]}",
            )
            agent.shared_data.this_device.ticket_order = 0
            agent.executor._execute_one_time_intialize_agent_or_server()
            self.agents.append(agent)
    def check_params_issue(self, from_agent, to_agent, ticket_type):
        if from_agent < 0 or from_agent > len(self.agents) - 1:
            print("Invalid from_agent")
            return False
        if to_agent < 0 or to_agent > len(self.agents) - 1:
            print("Invalid to_agent")
            return False
        if ticket_type not in self.types:
            print("Invalid ticket_type")
            return False
        return True
    def check_params_apply(self, agent):
        if agent < 0 or agent > len(self.agents) - 1:
            print("Invalid agent")
            return False
        return True

    def generate_request(self, to_agent, ticket_type, device_id = "no_id"):
        u_ticket_type = ""
        if ticket_type == "init": u_ticket_type = u_ticket.TYPE_INITIALIZATION_UTICKET
        elif ticket_type == "own": u_ticket_type = u_ticket.TYPE_OWNERSHIP_UTICKET
        elif ticket_type == "saccess": u_ticket_type = u_ticket.TYPE_SELFACCESS_UTICKET
        elif ticket_type == "access": u_ticket_type = u_ticket.TYPE_ACCESS_UTICKET
        generated_request: dict = {
            "device_id": f"{device_id}",
            "holder_id": f"{to_agent.shared_data.this_person.person_pub_key_str}",
            "u_ticket_type": f"{u_ticket_type}",
        }
        if "access" in ticket_type:
            generated_task_scope = dict_to_jsonstr({"ALL": "allow"})
            generated_request["task_scope"] = f"{generated_task_scope}"

        return generated_request
    def wait_for_voting_machine(self):
        start_time = time.time()
        while True:
            # wait for cummunicating agent to finish
            if self.cummunicating_agent is None:
                break
            # if wait too long, raise error
            print("Waiting for voting machine ", time.time() - start_time)
            if time.time() - start_time > 10:
                logger.error("vote machine timeout")
                print("vote machine timeout")
                break
            time.sleep(1)
    def issue(self, from_agent: int, to_agent: int, ticket_type: str):
        # check params
        if not self.check_params_issue(from_agent, to_agent, ticket_type):
            return -1
        # Get the device_id only if device_table is not empty
        device_keys = list(self.agents[from_agent].shared_data.device_table.keys())
        request = self.generate_request(self.agents[to_agent], ticket_type, device_keys[-1] if device_keys else "no_id")
        logger.debug(f"Request: {request}")
        if from_agent == to_agent:
            self.agents[from_agent].flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_herself(
                device_id=request["device_id"], arbitrary_dict=request
            )
        else:
            self.agents[from_agent].flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_holder(
                device_id=request["device_id"], arbitrary_dict=request
            )
            self.agents[to_agent].msg_receiver._recv_xxx_message()
    def holder_send_r_ticket(self, from_agent: int, to_agent: int):
        # check params
        if not self.check_params_apply(from_agent):
            return -1
        # check if agent have any unuse ticket

        device_keys = list(self.agents[from_agent].shared_data.device_table.keys())
        if not device_keys:
            logger.error("No unuse ticket")
            print("No unuse ticket")
            return -1
        target_id = device_keys[-1]
        self.agents[from_agent].flow_issuer_issue_u_ticket.holder_send_r_ticket_to_issuer(target_id)
        self.agents[to_agent].msg_receiver._recv_xxx_message()
    def apply(self, agent: int, command="HELLO-1"):
        # check params
        if not self.check_params_apply(agent):
            return -1
        # check if agent have any unuse ticket
        unuse_ticket_list = [key for key in self.agents[agent].shared_data.device_table]
        # logger.debug(f"Unuse ticket: {unuse_ticket_list}")
        if not unuse_ticket_list:
            logger.error("No unuse ticket")
            print("No unuse ticket")
            return -1
        
        environment.initialize()
        if command == "":
            command = "HELLO-1"
        self.agents[agent].flow_apply_u_ticket.holder_apply_u_ticket(unuse_ticket_list[0], command)
        self.cummunicating_agent = agent
        self.my_serial.send_data(environment.my_ticket)

        self.wait_for_voting_machine()


        
    def token(self, agent: int, command="HELLO-1"):
        if not self.check_params_apply(agent):
            return -1
        # check if agent have any unuse ticket
        unuse_ticket_list = [key for key in self.agents[agent].shared_data.device_table]
        # logger.debug(f"Unuse ticket: {unuse_ticket_list}")
        if not unuse_ticket_list:
            logger.error("No unuse ticket")
            print("No unuse ticket")
            return -1
        
        environment.initialize()
        self.agents[agent].flow_issue_u_token.holder_send_cmd(unuse_ticket_list[0], command, ("ACCESS_END" in command))

        self.cummunicating_agent = agent
        self.my_serial.send_data(environment.my_ticket)
        
        self.wait_for_voting_machine()
    def permissionless(self, agent: int):
        if not self.check_params_apply(agent):
            return -1
        
        generated_request = "{\"message_operation\":\"PERMISSIONLESS\",\"message_type\":\"PERMISSIONLESS\",\"message_str\":\"\"}"
        self.cummunicating_agent = agent
        self.my_serial.send_data(generated_request)

        self.wait_for_voting_machine()
            



def main():
    my_manager = DeviceManager()
    my_serial = MySerial(serial_port_name, baud_rate, my_manager)
    my_manager.my_serial = my_serial
    my_serial.start_reading()
    config_num = 0
    try:
        while True:
            questions = [
                inquirer.List('action',
                    message="What do you want to do?",
                    choices=["init", "own", "config", "voter", "tally", "permissionless", "quit"],
                ),
            ]
            action = inquirer.prompt(questions)["action"]
        # for action in ["init", "own", "config", "vote1", "vote2", "tally"]:
            if action == "init":
                my_manager.issue(0, 0, "init")
                my_manager.apply(0, "")
                print("Init done")
            elif action == "own":
                my_manager.issue(0, 1, "own")
                my_manager.apply(1, "")
                print("Own done")
            elif action == "config":
                my_manager.issue(1, 1, "saccess")
                my_manager.apply(1, "")
                # for i in range(2):
                my_manager.token(1, f"C!")
                for i in ["alice", "bob"]:
                    # questions = [
                    #     inquirer.Text('command',
                    #         message=f"Input command for candidate{i+1}",
                    #     ),
                    # ]
                    my_manager.token(1, f"C:{i}")
                print("Config candidate done")
                questions = [
                        inquirer.Text('command',
                            message=f"how many voter?",
                        ),
                    ]
                num_voter = int(inquirer.prompt(questions)["command"])
                list_voter = [2+i for i in range(num_voter)]
                config_num = num_voter
                
                for i in list_voter:
                    # questions = [
                    #     inquirer.Text('command',
                    #         message=f"Input command for voter{i+1}",
                    #     ),
                    # ]
                    my_manager.token(1, f"C-{my_manager.agents[i].shared_data.this_person.person_pub_key_str}")
                    print("config ", my_manager.agents[i].shared_data.this_person.person_pub_key_str, " done")
                my_manager.token(1, "ACCESS_END_C")
                print("Config voter done")
            elif action == "voter":
                
                questions = [
                    inquirer.List('command',
                        message=f"Which voter?",
                        choices=[f"{2+i}: {my_manager.agent_name[2+i]}" for i in range(config_num) if "User" in my_manager.agent_name[2+i]],
                    ),
                ]
                voter_agent = int(inquirer.prompt(questions)["command"].split(":")[0])
                my_manager.issue(1, voter_agent, "access")
                my_manager.apply(voter_agent, "")
                my_manager.token(voter_agent, f"A")
                questions = [
                    inquirer.List('candidate',
                        message=f"Which candidate?",
                        choices=["0", "1"],
                    ),
                ]
                vote_to = int(inquirer.prompt(questions)["candidate"])
                my_manager.token(voter_agent, f"V:{vote_to}")
                my_manager.token(voter_agent, f"ACCESS_END")
                my_manager.holder_send_r_ticket(voter_agent, 1)
                print("Vote1 done")
            elif action == "vote2":
                my_manager.issue(1, 3, "access")
                my_manager.apply(3, "")
                questions = [
                    inquirer.Text('command',
                        message=f"Input command for voter1",
                    ),
                ]
                my_manager.token(3, f"A")
                my_manager.token(3, f"V:0")
                my_manager.token(3, f"ACCESS_END")
                my_manager.holder_send_r_ticket(3, 1)
                print("Vote2 done")
            elif action == "vote3":
                my_manager.issue(1, 4, "access")
                my_manager.apply(4, "")
                questions = [
                    inquirer.Text('command',
                        message=f"Input command for voter1",
                    ),
                ]
                my_manager.token(4, f"A")
                my_manager.token(4, f"V:0")
                my_manager.token(4, f"ACCESS_END")
                my_manager.holder_send_r_ticket(4, 1)
                print("Vote3 done")
            elif action == "tally":
                my_manager.issue(1, 1, "saccess")
                my_manager.apply(1, "")
                my_manager.token(1, "TC")
                # input("Press Enter to continue...")
                my_manager.token(1, "TV0")
                my_manager.token(1, "TV1")
                my_manager.token(1, "TV2")
                # while True:
                #     questions = [
                #     inquirer.Text('command',
                #         message="Input command",
                #     ),
                #     ]
                #     command = inquirer.prompt(questions)["command"]
                #     if command == "quit":
                #         break
                #     my_manager.token(1, command)
                my_manager.token(1, "ACCESS_END_T")
                print("Tally done")
            elif action == "permissionless":
                my_manager.permissionless(1)
                print("Permissionless done")
            elif action == "quit":
                break


                
    finally:
        my_serial.stop_reading()
        print("Serial port closed, susppended")

def main_ureka():
    my_manager = DeviceManager()
    my_serial = MySerial(serial_port_name, baud_rate, my_manager)
    my_manager.my_serial = my_serial
    my_serial.start_reading()
    try :
        while True:
            questions = [
                inquirer.List('from_agent',
                    message="From which agent?",
                    choices=[f"{i}: {my_manager.agent_name[i]}" for i in range(len(my_manager.agents))],
                ),
                inquirer.List('action',
                    message="What do you want to do?",
                    choices=["issue", "apply", "token", "access end", "permissionless", "quit"],
                ),
            ]
            answers = inquirer.prompt(questions)
            from_agent = int(answers["from_agent"][0])
            action = answers["action"]

            if action == "quit":
                break
            elif action == "issue":
                questions = [
                    
                    inquirer.List('to_agent',
                        message="To which agent?",
                        choices=[f"{i}: {my_manager.agent_name[i]}" for i in range(len(my_manager.agents))],
                    ),
                    inquirer.List('ticket_type',
                        message="Which ticket type?",
                        choices=my_manager.types,
                    ),
                ]
                answers = inquirer.prompt(questions)
                
                to_agent = int(answers["to_agent"][0])
                ticket_type = answers["ticket_type"]
                my_manager.issue(from_agent, to_agent, ticket_type)
            elif action == "apply":
                questions = [
                    inquirer.Text('command',
                        message="Input command",
                    ),
                ]
                answers = inquirer.prompt(questions)
                command = answers["command"]
                my_manager.apply(from_agent, command)
            elif action == "token":
                questions = [
                    inquirer.Text('command',
                        message="Input command",
                    ),
                ]
                answers = inquirer.prompt(questions)
                command = answers["command"]
                my_manager.token(from_agent, command)
            elif action == "access end":
                my_manager.token(from_agent, "ACCESS_END")
            elif action == "permissionless":
                my_manager.permissionless(from_agent)
            
    finally:
        my_serial.stop_reading()
        print("Serial port closed, susppended")
    
        
    

if __name__ == "__main__":
    main()