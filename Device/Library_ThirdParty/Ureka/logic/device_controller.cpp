#include "device_controller.hpp"

DeviceController::DeviceController(const std::string &device_type, const std::string &device_name)
{
    initialize();

    // 设置设备类型（必须在加载存储后进行）
    if (!shared_data->this_device.has_device_type)
    {
        executor->self_execute_one_time_set_time_device_type_and_name(device_type, device_name);
        printf("info: Set device type and name to %s, %s\n", device_type.c_str(), device_name.c_str());
    }

    // 设置初始化状态
    executor->self_initialize_state();

    // simple_log("info", "+ Here is a " + shared_data->this_device.device_name + "...");
    printf("info: Here is a %s...\n", shared_data->this_device.device_name.c_str());
}

DeviceController::~DeviceController()
{
    cleanup();
}

void DeviceController::reboot_device()
{
    // simple_log("info", "+ Reboot " + shared_data->this_device.device_name + "...");
    printf("info: Reboot %s...\n", shared_data->this_device.device_name.c_str());
    cleanup();
    initialize();
}

void DeviceController::initialize()
{
    // 初始化所有组件
    shared_data = new SharedData();
    simple_storage = new SimpleStorage(shared_data->this_device.device_name);
    // measure_helper = new MeasureHelper(shared_data);

    // 初始化 Stage Workers
    // received_msg_storer = new ReceivedMsgStorer(shared_data, simple_storage);
    msg_verifier = new MsgVerifier(shared_data);
    executor = new Executor(shared_data /*, simple_storage, msg_verifier*/);
    msg_generator = new MsgGenerator(shared_data);
    // generated_msg_storer = new GeneratedMsgStorer(shared_data /*, *simple_storage*/);
    msg_sender = new MsgSender(shared_data);

    // 初始化 Flows
    flow_issuer_issue_u_ticket = new FlowIssueUTicket(shared_data, received_msg_storer, msg_verifier, executor, msg_generator, generated_msg_storer, msg_sender);
    flow_open_session = new FlowOpenSession(shared_data, received_msg_storer, msg_verifier, executor, msg_generator, generated_msg_storer, msg_sender);
    flow_apply_u_ticket = new FlowApplyUTicket(shared_data, received_msg_storer, msg_verifier, executor, msg_generator, generated_msg_storer, msg_sender, flow_open_session);
    flow_issue_u_token = new FlowIssueUToken(shared_data, received_msg_storer, msg_verifier, executor, msg_generator, generated_msg_storer, msg_sender, flow_apply_u_ticket);

    // 初始化 MsgReceiver
    msg_receiver = new MsgReceiver(shared_data, msg_verifier, executor, msg_sender, flow_issuer_issue_u_ticket, flow_apply_u_ticket, flow_open_session, flow_issue_u_token);

    // 加载存储
    simple_storage->load_storage(shared_data->this_device, shared_data->device_table, shared_data->this_person, shared_data->current_session);
}

void DeviceController::cleanup()
{
    delete msg_receiver;
    // delete flow_issue_u_token;
    // delete flow_apply_u_ticket;
    // delete flow_open_session;
    delete flow_issuer_issue_u_ticket;
    delete msg_sender;
    delete generated_msg_storer;
    delete msg_generator;
    delete executor;
    delete msg_verifier;
    delete received_msg_storer;
    // delete  _helper;
    delete simple_storage;
    delete shared_data;
}