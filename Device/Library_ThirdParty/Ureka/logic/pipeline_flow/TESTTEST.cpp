#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "ureka_framework/resource/storage/simple_storage.h"
#include "ureka_framework/logic/device_controller.h"
#include "ureka_framework/model/message_model/u_ticket.h"
#include "ureka_framework/model/data_model/this_device.h"
#include "tests/conftest.h"

class TestSuccessWhenIntializeDevice : public ::testing::Test {
protected:
    void SetUp() override {
        current_setup_log();
        SimpleStorage::delete_storage_in_test();
    }

    void TearDown() override {
        current_teardown_log();
        SimpleStorage::delete_storage_in_test();
    }

    DeviceManufacturerServer cloud_server_dm;
    DeviceController iot_device;
};

TEST_F(TestSuccessWhenIntializeDevice, SuccessWhenApplyInitializationUTicketOnDevice) {
    current_test_given_log();

    // GIVEN: Initialized DM's CS
    cloud_server_dm = device_manufacturer_server();

    // GIVEN: Uninitialized IoTD
    iot_device = DeviceController(this_device::IOT_DEVICE, "iot_device");
    ASSERT_EQ(iot_device.shared_data.this_device.ticket_order, 0);
    ASSERT_EQ(iot_device.shared_data.this_device.device_priv_key_str, nullptr);
    ASSERT_EQ(iot_device.shared_data.this_device.device_pub_key_str, nullptr);
    ASSERT_EQ(iot_device.shared_data.this_device.owner_pub_key_str, nullptr);
    ASSERT_EQ(iot_device.shared_data.this_person.person_priv_key_str, nullptr);
    ASSERT_EQ(iot_device.shared_data.this_person.person_pub_key_str, nullptr);

    current_test_when_and_then_log();

    // WHEN: Issuer: DM's CS generate the intialization_u_ticket to herself
    std::string id_for_initialization_u_ticket = "no_id";
    std::map<std::string, std::string> generated_request = {
        {"device_id", id_for_initialization_u_ticket},
        {"holder_id", cloud_server_dm.shared_data.this_person.person_pub_key_str},
        {"u_ticket_type", u_ticket::TYPE_INITIALIZATION_UTICKET}
    };
    cloud_server_dm.flow_issuer_issue_u_ticket.issuer_issue_u_ticket_to_herself(
        id_for_initialization_u_ticket, generated_request);

    // WHEN: Holder: DM's CS forward the access_u_ticket to Uninitialized IoTD
    create_simulated_comm_connection(cloud_server_dm, iot_device);
    cloud_server_dm.flow_apply_u_ticket.holder_apply_u_ticket(id_for_initialization_u_ticket);
    wait_simulated_comm_completed(cloud_server_dm, iot_device);

    // THEN: Succeed to initialize DM's IoTD
    ASSERT_THAT(iot_device.shared_data.result_message, ::testing::HasSubstr("SUCCESS"));
    ASSERT_THAT(cloud_server_dm.shared_data.result_message, ::testing::HasSubstr("SUCCESS"));

    // THEN: Device: Set New Owner, Update ticket order
    ASSERT_EQ(iot_device.shared_data.this_device.ticket_order, 1);
    ASSERT_NE(iot_device.shared_data.this_device.device_priv_key_str, nullptr);
    ASSERT_NE(iot_device.shared_data.this_device.device_pub_key_str, nullptr);
    ASSERT_EQ(iot_device.shared_data.this_device.owner_pub_key_str,
              cloud_server_dm.shared_data.this_person.person_pub_key_str);
    ASSERT_EQ(iot_device.shared_data.this_person.person_priv_key_str, nullptr);
    ASSERT_EQ(iot_device.shared_data.this_person.person_pub_key_str, nullptr);
}

TEST_F(TestSuccessWhenIntializeDevice, SuccessWhenRebootDevice) {
    current_test_given_log();

    // GIVEN: Initialized DM's CS and DM's IoTD
    std::tie(cloud_server_dm, iot_device) = device_manufacturer_server_and_her_device();

    // WHEN: Reboot DM's IoTD
    current_test_when_and_then_log();
    iot_device.reboot_device();

    // THEN: Still be Initialized DM's IoTD
    ASSERT_EQ(iot_device.shared_data.this_device.ticket_order, 1);
    ASSERT_NE(iot_device.shared_data.this_device.device_priv_key_str, nullptr);
    ASSERT_NE(iot_device.shared_data.this_device.device_pub_key_str, nullptr);
    ASSERT_EQ(iot_device.shared_data.this_device.owner_pub_key_str,
              cloud_server_dm.shared_data.this_person.person_pub_key_str);
    ASSERT_EQ(iot_device.shared_data.this_person.person_priv_key_str, nullptr);
    ASSERT_EQ(iot_device.shared_data.this_person.person_pub_key_str, nullptr);
}