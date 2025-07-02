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

#include <libsinsp/state/dynamic_struct.h>
#include <libsinsp/sinsp_exception.h>
#include <libsinsp/state/base_field.h>
#include <libsinsp/state/table.h>

using namespace libsinsp::state;

// CRTP base for type-erased dynamic field accessors
template<typename Derived>
class dynamic_field_accessor_base : public base_field_accessor {
public:
	explicit dynamic_field_accessor_base(const dynamic_struct::field_info& info): m_info(info) {}

	void read_value(const table_entry& entry, void* out) const override {
		static_cast<const Derived*>(this)->read_value_impl(entry, out);
	}

	void write_value(table_entry& entry, const void* in) const override {
		static_cast<const Derived*>(this)->write_value_impl(entry, in);
	}

protected:
	const dynamic_struct::field_info& m_info;
};

// Concrete implementation for specific types
template<typename T>
class dynamic_field_accessor_impl
        : public dynamic_field_accessor_base<dynamic_field_accessor_impl<T>> {
public:
	explicit dynamic_field_accessor_impl(const dynamic_struct::field_info& info):
	        dynamic_field_accessor_base<dynamic_field_accessor_impl<T>>(info),
	        m_accessor(info.template new_accessor<T>()) {}

	void read_value_impl(const table_entry& entry, void* out) const {
		const auto& dynamic_entry = static_cast<const dynamic_struct&>(entry);
		T value;
		const_cast<dynamic_struct&>(dynamic_entry).get_dynamic_field(m_accessor, value);
		*static_cast<T*>(out) = value;
	}

	void write_value_impl(table_entry& entry, const void* in) const {
		auto& dynamic_entry = static_cast<dynamic_struct&>(entry);
		const T& value = *static_cast<const T*>(in);
		dynamic_entry.set_dynamic_field(m_accessor, value);
	}

private:
	typename dynamic_struct::field_accessor<T> m_accessor;
};

// Template metaprogramming for type dispatch
template<typename... Types>
struct type_dispatcher;

template<typename T, typename... Rest>
struct type_dispatcher<T, Rest...> {
	static std::unique_ptr<base_field_accessor> create(const dynamic_struct::field_info& info,
	                                                   const typeinfo& type) {
		if(type == typeinfo::of<T>()) {
			return std::make_unique<dynamic_field_accessor_impl<T>>(info);
		}
		return type_dispatcher<Rest...>::create(info, type);
	}
};

template<>
struct type_dispatcher<> {
	static std::unique_ptr<base_field_accessor> create(const dynamic_struct::field_info&,
	                                                   const typeinfo&) {
		return nullptr;
	}
};

// Type list for supported dynamic field types
using supported_dynamic_types =
        type_dispatcher<std::string, int64_t, uint64_t, int32_t, uint32_t, bool, double
                        // Adding new types is as simple as adding them to this list:
                        // , float, int16_t, uint16_t, int8_t, uint8_t, custom_type
                        >;

// Clean factory function using template metaprogramming
static std::unique_ptr<base_field_accessor> create_dynamic_accessor(
        const dynamic_struct::field_info& info,
        const typeinfo& type) {
	return supported_dynamic_types::create(info, type);
}

// Implementation of the virtual method
std::unique_ptr<base_field_accessor> dynamic_struct::field_info::new_accessor(
        const typeinfo& type) const {
	if(!valid()) {
		return nullptr;
	}

	if(info() != type) {
		return nullptr;
	}

	return create_dynamic_accessor(*this, type);
}
