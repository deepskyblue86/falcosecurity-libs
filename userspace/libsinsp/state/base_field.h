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

#pragma once

#include <libsinsp/state/type_info.h>
#include <string>
#include <memory>

namespace libsinsp {
namespace state {

struct table_entry;

/**
 * @brief Type-erased base accessor for field access operations
 */
class base_field_accessor {
public:
	virtual ~base_field_accessor() = default;

	virtual void read_value(const table_entry& entry, void* out) const = 0;
	virtual void write_value(table_entry& entry, const void* in) const = 0;
};

/**
 * @brief Base class for field information, abstracting
 * differences between static and dynamic fields
 */
class base_field_info {
public:
	virtual ~base_field_info() = default;

	// Common interface that all field info types must implement
	virtual const std::string& name() const = 0;
	virtual const typeinfo& info() const = 0;
	virtual bool readonly() const = 0;
	virtual bool valid() const = 0;

	virtual std::unique_ptr<base_field_accessor> new_accessor(const typeinfo& type) const = 0;
};

}  // namespace state
}  // namespace libsinsp
