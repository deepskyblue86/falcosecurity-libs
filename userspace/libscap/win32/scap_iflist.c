/*
Copyright (C) 2021 The Falco Authors.

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

#include <stdio.h>

#include "scap.h"
#include "scap-int.h"
#include "../common/strlcpy.h"


#include "windows_hal.h"

int32_t scap_create_iflist(scap_t* handle)
{
	return scap_create_iflist_windows(handle);
}


void scap_refresh_iflist(scap_t* handle)
{
	scap_free_iflist(handle->m_addrlist);
	handle->m_addrlist = NULL;
	scap_create_iflist(handle);
}

