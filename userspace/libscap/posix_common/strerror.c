/*
Copyright (C) 2022 The Falco Authors.

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


#include <errno.h>
#include <stdio.h>

#include "scap.h"
#include "scap-int.h"

const char *scap_strerror_r(char *buf, int errnum)
{
	int rc;
	if((rc = strerror_r(errnum, buf, SCAP_LASTERR_SIZE) != 0))
	{
		if(rc != ERANGE)
		{
			snprintf(buf, SCAP_LASTERR_SIZE, "Errno %d", errnum);
		}
	}

	return buf;
}

const char *scap_strerror(scap_t *handle, int errnum)
{
	return scap_strerror_r(handle->m_strerror_buf, errnum);
}

