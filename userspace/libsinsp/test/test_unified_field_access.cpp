// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include <gtest/gtest.h>
#include <libsinsp/state/table.h>

using namespace libsinsp::state;

class UnifiedFieldAccessTest : public ::testing::Test {
protected:
	void SetUp() override {
		// Create dynamic fields for testing
		m_dynamic_fields = std::make_shared<dynamic_struct::field_infos>();

		// Add some dynamic fields
		m_dynamic_fields->add_field<std::string>("container_id");
		m_dynamic_fields->add_field<int64_t>("vpid");
		m_dynamic_fields->add_field<bool>("host_pid");

		// Create table entry
		m_entry = std::make_unique<table_entry>(m_dynamic_fields);
	}

	std::shared_ptr<dynamic_struct::field_infos> m_dynamic_fields;
	std::unique_ptr<table_entry> m_entry;
};

TEST_F(UnifiedFieldAccessTest, FieldExistenceCheck) {
	// Test has_field for dynamic fields that exist in schema
	EXPECT_TRUE(m_entry->has_field("container_id"));  // Field exists in schema
	EXPECT_TRUE(m_entry->has_field("vpid"));
	EXPECT_TRUE(m_entry->has_field("host_pid"));

	// Test non-existent field
	EXPECT_FALSE(m_entry->has_field("nonexistent_field"));
}

TEST_F(UnifiedFieldAccessTest, DynamicFieldAccess) {
	// Set some dynamic field values using accessors (existing API)
	const auto& fields = m_dynamic_fields->fields();
	auto container_id_accessor = fields.at("container_id").new_accessor<std::string>();
	auto vpid_accessor = fields.at("vpid").new_accessor<int64_t>();
	auto host_pid_accessor = fields.at("host_pid").new_accessor<bool>();

	m_entry->set_dynamic_field(container_id_accessor, std::string("test-container-123"));
	m_entry->set_dynamic_field(vpid_accessor, int64_t(42));
	m_entry->set_dynamic_field(host_pid_accessor, true);

	// Now test unified field access API

	// Test get_field_or with defaults
	std::string container_id = m_entry->get_field_or<std::string>("container_id", "default");
	EXPECT_EQ(container_id, "test-container-123");

	int64_t vpid = m_entry->get_field_or<int64_t>("vpid", -1);
	EXPECT_EQ(vpid, 42);

	bool host_pid = m_entry->get_field_or<bool>("host_pid", false);
	EXPECT_TRUE(host_pid);

	// Test non-existent field returns default
	std::string nonexistent = m_entry->get_field_or<std::string>("nonexistent", "default_value");
	EXPECT_EQ(nonexistent, "default_value");

	// Test optional access
	auto maybe_container_id = m_entry->get_field<std::string>("container_id");
	ASSERT_TRUE(maybe_container_id.has_value());
	EXPECT_EQ(*maybe_container_id, "test-container-123");

	auto maybe_nonexistent = m_entry->get_field<std::string>("nonexistent");
	EXPECT_FALSE(maybe_nonexistent.has_value());
}

TEST_F(UnifiedFieldAccessTest, FieldTypeIntrospection) {
	// Test get_field_type for dynamic fields
	auto container_id_type = m_entry->get_field_type("container_id");
	ASSERT_TRUE(container_id_type.has_value());
	EXPECT_EQ(container_id_type->type_id(), SS_PLUGIN_ST_STRING);

	auto vpid_type = m_entry->get_field_type("vpid");
	ASSERT_TRUE(vpid_type.has_value());
	EXPECT_EQ(vpid_type->type_id(), SS_PLUGIN_ST_INT64);

	auto host_pid_type = m_entry->get_field_type("host_pid");
	ASSERT_TRUE(host_pid_type.has_value());
	EXPECT_EQ(host_pid_type->type_id(), SS_PLUGIN_ST_BOOL);

	// Test non-existent field
	auto nonexistent_type = m_entry->get_field_type("nonexistent");
	EXPECT_FALSE(nonexistent_type.has_value());
}

TEST_F(UnifiedFieldAccessTest, FieldSetting) {
	// Test setting dynamic fields through unified API
	bool success_container = m_entry->set_field("container_id", std::string("new-container-456"));
	EXPECT_TRUE(success_container);

	bool success_vpid = m_entry->set_field("vpid", int64_t(999));
	EXPECT_TRUE(success_vpid);

	bool success_host_pid = m_entry->set_field("host_pid", false);
	EXPECT_TRUE(success_host_pid);

	// Verify the values were set correctly
	EXPECT_EQ(m_entry->get_field_or<std::string>("container_id", ""), "new-container-456");
	EXPECT_EQ(m_entry->get_field_or<int64_t>("vpid", -1), 999);
	EXPECT_FALSE(m_entry->get_field_or<bool>("host_pid", true));

	// Test setting non-existent field
	bool success_nonexistent = m_entry->set_field("nonexistent", std::string("value"));
	EXPECT_FALSE(success_nonexistent);

	// Test setting with wrong type
	bool success_wrong_type = m_entry->set_field("container_id", int64_t(123));
	EXPECT_FALSE(success_wrong_type);
}

TEST_F(UnifiedFieldAccessTest, ReadOnlyCheck) {
	// Test is_field_readonly
	bool readonly_container = m_entry->is_field_readonly("container_id");
	EXPECT_FALSE(readonly_container);  // Dynamic fields are typically not read-only

	bool readonly_nonexistent = m_entry->is_field_readonly("nonexistent");
	EXPECT_TRUE(readonly_nonexistent);  // Non-existent fields are considered read-only
}

TEST_F(UnifiedFieldAccessTest, GetFieldInfo) {
	// Test get_field_info returns valid base_field_info
	auto container_id_info = m_entry->get_field_info("container_id");
	ASSERT_NE(container_id_info, nullptr);
	EXPECT_EQ(container_id_info->name(), "container_id");
	EXPECT_EQ(container_id_info->kind(), base_field_info::DYNAMIC);
	EXPECT_TRUE(container_id_info->valid());
	EXPECT_FALSE(container_id_info->readonly());

	// Test non-existent field
	auto nonexistent_info = m_entry->get_field_info("nonexistent");
	EXPECT_EQ(nonexistent_info, nullptr);
}

TEST_F(UnifiedFieldAccessTest, TypeSafety) {
	// Set up a field with a known value
	m_entry->set_field("vpid", int64_t(42));

	// Test correct type access
	auto correct_value = m_entry->get_field<int64_t>("vpid");
	ASSERT_TRUE(correct_value.has_value());
	EXPECT_EQ(*correct_value, 42);

	// Test wrong type access (should return nullopt)
	auto wrong_type_value = m_entry->get_field<std::string>("vpid");
	EXPECT_FALSE(wrong_type_value.has_value());

	// Test wrong type with default (should return default)
	std::string wrong_type_default = m_entry->get_field_or<std::string>("vpid", "default");
	EXPECT_EQ(wrong_type_default, "default");
}

// Test demonstrating the API improvement over the verbose old approach
TEST(UnifiedFieldAccessDemo, VerbosityImprovement) {
	// Create a table entry for demonstration
	auto dynamic_fields = std::make_shared<dynamic_struct::field_infos>();
	dynamic_fields->add_field<std::string>("container_id");
	table_entry entry(dynamic_fields);

	// Set up the field value using the old accessor method
	const auto& fields = dynamic_fields->fields();
	auto accessor = fields.at("container_id").new_accessor<std::string>();
	entry.set_dynamic_field(accessor, std::string("test-container"));

	// OLD VERBOSE APPROACH (what we replaced):
	// std::string container_id;
	// const auto field_info = dynamic_fields->get_field<std::string>("container_id");
	// auto field_accessor = field_info.new_accessor<std::string>();
	// try {
	//     entry.get_dynamic_field(field_accessor, container_id);
	// } catch(...) {
	//     container_id = ""; // default
	// }

	// NEW UNIFIED APPROACH (our implementation):
	std::string container_id = entry.get_field_or<std::string>("container_id", "");

	// Verify it works
	EXPECT_EQ(container_id, "test-container");

	// This demonstrates:
	// - 7+ lines reduced to 1 line (85%+ reduction)
	// - Built-in error handling
	// - Type safety
	// - Works for both static and dynamic fields
	// - No need to manage accessors manually
}
