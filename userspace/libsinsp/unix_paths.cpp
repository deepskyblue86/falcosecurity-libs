// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include "unix_paths.h"
#include "cwalk.h"

#include <filesystem>

namespace unix_paths {

#ifdef _WIN32
static std::filesystem::path workaround_win_root_name(std::filesystem::path p)
{
	if (!p.has_root_name())
	{
		return p;
	}

	if (p.root_name().string().rfind("//", 0) == 0)
	{
		// this is something like //dir/hello. Add a leading slash to identify an absolute path rooted at /
		return std::filesystem::path("/" + p.string());
	}

	// last case: this is a relative path, like c:/dir/hello. Add a leading ./ to identify a relative path
	return std::filesystem::path("./" + p.string());
}
#endif

static std::string concatenate_paths_fs(std::string_view path1, std::string_view path2, size_t max_len)
{
    auto p1 = std::filesystem::path(path1, std::filesystem::path::format::generic_format);
    auto p2 = std::filesystem::path(path2, std::filesystem::path::format::generic_format);

#ifdef _WIN32
	// This is an ugly workaround to make sure we will not try to interpret root names (e.g. "c:/", "//?/") on Windows
	// since this function only deals with unix-like paths
	p1 = workaround_win_root_name(p1);
	p2 = workaround_win_root_name(p2);
#endif // _WIN32

	// note: if p2 happens to be an absolute path, p1 / p2 == p2
	auto path_concat = (p1 / p2).lexically_normal();
	std::string result = path_concat.generic_string();

	//
	// If the path ends with a separator, remove it, as the OS does.
	//
	if (result.length() > 1 && result.back() == '/')
	{
		result.pop_back();
	}

	if (result.length() > max_len)
	{
		return "/PATH_TOO_LONG";
	}

	return result;
}

class cwalk_state
{
public:
	cwalk_state()
	{
		m_buf = nullptr;
		m_size = 0;
	}

	~cwalk_state()
	{
		if (m_buf != nullptr)
		{
			free(m_buf);
		}
	}

	void ensure_buf(size_t size)
	{
		if (m_size < size)
		{
			m_buf = (char*) malloc(size);
			m_size = size;

			// err handling?
		}
	}

	char* m_buf;
	size_t m_size;
};

static cwalk_state state;

static std::string concatenate_paths_cwalk(std::string_view path1, std::string_view path2, size_t max_len)
{
	state.ensure_buf(max_len + 1);
	// size_t cwk_path_join(const char *path_a, const char *path_b, char *buffer, size_t buffer_size);

	size_t complete_size;

	if (path1.data() == nullptr || path1.size() == 0 || cwk_path_is_absolute(path2.data()))
	{
		complete_size = cwk_path_normalize(path2.data(), state.m_buf, state.m_size);
	} else
	{
		complete_size = cwk_path_join(path1.data(), path2.data(), state.m_buf, state.m_size);
	}

	if (complete_size > max_len)
	{
		return "/PATH_TOO_LONG";
	}
	return std::string(state.m_buf);
}


std::string concatenate_paths(std::string_view path1, std::string_view path2, size_t max_len)
{
	return concatenate_paths_cwalk(path1, path2, max_len);
}

} // namespace unix_paths